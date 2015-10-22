package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.sos.web.SOSWebRoutable;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;

/**
 * Steroid OpenFlow Service Module
 * @author Ryan Izard, rizard@g.clemson.edu
 * 
 */
public class SOS implements IOFMessageListener, IOFSwitchListener, IFloodlightModule, ISOSService  {
	private static final Logger log = LoggerFactory.getLogger(SOS.class);
	protected static IFloodlightProviderService floodlightProvider;
	protected static IOFSwitchService switchService;
	private static IRoutingService routingService;
	private static IDeviceService deviceService;
	protected static IStaticFlowEntryPusherService sfp;
	private static IRestApiService restApiService;
	private static ITopologyService topologyService;
	private static IThreadPoolService threadPoolService;

	private static ScheduledFuture<?> agentMonitor;

	private static MacAddress controllerMac;

	private static SOSConnections sosConnections;
	private static Set<SOSAgent> agents;

	private static boolean enabled;

	/* These needs to be constant b/t agents, thus we'll keep them global for now */
	private static int bufferSize;
	private static int agentQueueCapacity;
	private static int agentNumParallelSockets;
	private static short flowTimeout;

	/* Keep tabs on our agents; make sure dev mgr will have them cached */
	private class SOSAgentMonitor implements Runnable {
		@Override
		public void run() {
			try {
				for (SOSAgent a : agents) {
					/* Lookup agent's last known location */
					Iterator<? extends IDevice> i = deviceService.queryDevices(MacAddress.NONE, null, a.getIPAddr(), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
					SwitchPort sp = null;
					if (i.hasNext()) {
						IDevice d = i.next();
						SwitchPort[] agentAps = d.getAttachmentPoints();
						if (agentAps.length > 0) {
							SwitchPort agentTrueAp = findTrueAttachmentPoint(agentAps);
							if (agentTrueAp == null) {
								log.error("Could not determine true attachment point for agent {} when ARPing for agent. Report SOS bug.", a);
							} else {
								sp = agentTrueAp;
							}
						}
					} else {
						log.error("Device manager could not locate agent {}", a);
					}

					if (sp != null) { /* We know specifically where the agent is located */
						log.warn("ARPing for agent {} with known true attachment point {}", a, sp);
						arpForDevice(
								a.getIPAddr(), 
								(a.getIPAddr().and(IPv4Address.of("255.255.255.0"))).or(IPv4Address.of("0.0.0.254")) /* Doesn't matter really; must be same subnet though */, 
								MacAddress.BROADCAST /* Use broadcast as to not potentially confuse a host's ARP cache */, 
								VlanVid.ZERO /* Switch will push correct VLAN tag if required */, 
								switchService.getSwitch(sp.getSwitchDPID())
								);
					} else { /* We don't know where the agent is -- flood ARP everywhere */
						Set<DatapathId> switches = switchService.getAllSwitchDpids();
						log.warn("Agent {} does not have known/true attachment point(s). Flooding ARP on all switches", a);
						for (DatapathId sw : switches) {
							log.debug("Agent {} does not have known/true attachment point(s). Flooding ARP on switch {}", a, sw);
							arpForDevice(
									a.getIPAddr(), 
									(a.getIPAddr().and(IPv4Address.of("255.255.255.0"))).or(IPv4Address.of("0.0.0.254")) /* Doesn't matter really; must be same subnet though */, 
									MacAddress.BROADCAST /* Use broadcast as to not potentially confuse a host's ARP cache */, 
									VlanVid.ZERO /* Switch will push correct VLAN tag if required */, 
									switchService.getSwitch(sw)
									);
						}
					}
				}
			} catch (Exception e) {
				log.error("Caught exception in ARP monitor thread: {}", e);
			}
		}
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IOFSwitchService.class);
		l.add(IRoutingService.class);
		l.add(IDeviceService.class);
		l.add(IStaticFlowEntryPusherService.class);
		l.add(IRestApiService.class);
		l.add(ITopologyService.class);
		l.add(IThreadPoolService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		routingService = context.getServiceImpl(IRoutingService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		topologyService = context.getServiceImpl(ITopologyService.class);
		threadPoolService = context.getServiceImpl(IThreadPoolService.class);

		agents = new HashSet<SOSAgent>();
		sosConnections = new SOSConnections();
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);
		restApiService.addRestletRoutable(new SOSWebRoutable());

		/* Read our config options */
		Map<String, String> configOptions = context.getConfigParams(this);
		try {
			controllerMac = MacAddress.of(configOptions.get("controller-mac"));

			/* These are defaults */
			bufferSize = Integer.parseInt(configOptions.get("buffer-size"));
			agentQueueCapacity = Integer.parseInt(configOptions.get("queue-capacity"));
			agentNumParallelSockets = Integer.parseInt(configOptions.get("parallel-tcp-sockets"));
			flowTimeout = Short.parseShort(configOptions.get("flow-timeout"));
			enabled = Boolean.parseBoolean(configOptions.get("enabled") != null ? configOptions.get("enabled") : "true"); /* enabled by default if not present --> listing module is enabling */

		} catch (IllegalArgumentException | NullPointerException ex) {
			log.error("Incorrect SOS configuration options. Required: 'controller-mac', 'buffer-size', 'queue-capacity', 'parallel-tcp-sockets', 'flow-timeout', 'enabled'", ex);
			throw ex;
		}
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(ISOSService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(ISOSService.class, this);
		return m;
	}

	@Override
	public String getName() {
		return SOS.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		/* 
		 * Allow the CONTEXT_SRC/DST_DEVICE field to be populated by 
		 * the DeviceManager. This makes our job easier :) 
		 */
		if (type == OFType.PACKET_IN && name.equalsIgnoreCase("devicemanager")) {
			log.debug("SOS is telling DeviceManager to run before.");
			return true;
		} else {
			return false;
		}
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		if (type == OFType.PACKET_IN && (name.equals("forwarding") || name.equals("hub"))) {
			log.debug("SOS is telling Forwarding/Hub to run later.");
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Send a UDP information packet to an agent. This informs the agent of the SOS
	 * connection about to take place. For example, a client-side agent is informed of
	 * the server-side agent to connect to, the number of parallel sockets to open up,
	 * and so forth. A server-side agent is informed of the the number of parallel 
	 * connections to establish server sockets, the server IP itself, and so forth.
	 * 
	 * @param conn, The associated SOSConnection for the UDP info packets.
	 * @param isSourceAgent, Send to source agent (true); send to destination agent (false).
	 */
	private void sendInfoToAgent(FloodlightContext cntx, SOSConnection conn, boolean isClientSideAgent) {
		OFFactory factory;

		/* Both use route last-hop, since the packets are destined for the agents */
		if (isClientSideAgent) {
			factory = switchService.getSwitch(conn.getClientSideRoute().getRouteLastHop().getNodeId()).getOFFactory();
		} else {
			factory = switchService.getSwitch(conn.getServerSideRoute().getRouteLastHop().getNodeId()).getOFFactory();
		}

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* L2 of packet */
		Ethernet l2 = new Ethernet();
		l2.setSourceMACAddress(controllerMac);
		l2.setDestinationMACAddress(isClientSideAgent ? conn.getClientSideAgent().getMACAddr() : conn.getServerSideAgent().getMACAddr());
		l2.setEtherType(EthType.IPv4);
		log.trace("Set info packet destination MAC to {}", l2.getDestinationMACAddress());

		/* L3 of packet */
		IPv4 l3 = new IPv4();
		l3.setSourceAddress(isClientSideAgent ? conn.getServerSideAgent().getIPAddr() : conn.getServer().getIPAddr());
		l3.setDestinationAddress(isClientSideAgent ? conn.getClientSideAgent().getIPAddr() : conn.getServerSideAgent().getIPAddr());
		l3.setProtocol(IpProtocol.UDP);
		l3.setTtl((byte) 64);
		log.trace("Set info packet source IP to {}", l3.getSourceAddress());
		log.trace("Set info packet destination IP to {}", l3.getDestinationAddress());

		/* L4 of packet */
		UDP l4 = new UDP();
		l4.setSourcePort(conn.getServer().getTcpPort());
		l4.setDestinationPort(isClientSideAgent ? conn.getClientSideAgent().getControlPort() : conn.getServerSideAgent().getControlPort());
		log.trace("Set info packet source port to {}", l4.getSourcePort());
		log.trace("Set info packet destination port to {}", l4.getDestinationPort());

		/* 
		 * Convert the string into IPacket. Data extends BasePacket, which is an abstract class
		 * that implements IPacket. The only class variable of Data is the byte[] 'data'. The 
		 * deserialize() method of Data is the following:
		 * 
		 *  public IPacket deserialize(byte[] data, int offset, int length) {
		 *      this.data = Arrays.copyOfRange(data, offset, data.length);
		 *      return this;
		 *  }
		 *  
		 *  We provide the byte[] form of the string (ASCII code bytes) as 'data', and 0 as the
		 *  'offset'. The 'length' is not used and instead replaced with the length of the byte[].
		 *  Notice 'this' is returned. 'this' is the current Data object, which only has the single
		 *  byte[] 'data' as a class variable. This means that when 'this' is returned, it will
		 *  simply be a byte[] form of the original string as an IPacket instead.
		 */

		String agentInfo = null;
		if (isClientSideAgent) {
			/*payload = "CLIENT " + str(transfer_id) + 
					" " + ip_to_str(packet.next.srcip)  + 
					" " + str(packet.next.next.srcport) + 
					" " +  ip_to_str(inst.Agent[FA]['ip']) + 
					" "  + str(NUM_CONNECTIONS) + 
					" "  + str(BUFSIZE) + 
					" " +str(MAX_QUEUE_SIZE) */
			log.debug(conn.getTransferID().toString());
			agentInfo = "CLIENT " + conn.getTransferID().toString() + 
					" " + conn.getClient().getIPAddr().toString() +
					" " + conn.getClient().getTcpPort().toString() +
					" " + conn.getServerSideAgent().getIPAddr().toString() +
					" " + Integer.toString(conn.getNumParallelSockets()) +
					" " + Integer.toString(conn.getBufferSize()) +
					" " + Integer.toString(conn.getQueueCapacity());
		} else {
			/*payload = "AGENT " + str(transfer_id) + 
				" " + ip_to_str(packet.next.dstip)  + 
				" " + str(packet.next.next.dstport) + 
				"  " + str(NUM_CONNECTIONS) + 
				" " + str(BUFSIZE) + 
				" " + str(MAX_QUEUE_SIZE) */
			agentInfo = "AGENT " + conn.getTransferID().toString() + 
					" " + conn.getServer().getIPAddr().toString() +
					" " + conn.getServer().getTcpPort().toString() +
					/* 
					 * The server-side agent will learn the client-side agent IP
					 * after it receives the first TCP SYN packets from the
					 * client-side agent.
					 */
					" " + Integer.toString(conn.getNumParallelSockets()) +
					" " + Integer.toString(conn.getBufferSize()) +
					" " + Integer.toString(conn.getQueueCapacity());
		}

		Data payloadData = new Data();

		/* Construct the packet layer-by-layer */
		l2.setPayload(l3.setPayload(l4.setPayload(payloadData.setData(agentInfo.getBytes()))));

		/* 
		 * Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		if (isClientSideAgent) {
			log.debug("Sending client-side info packet to agent {} out switch+port {}", conn.getClientSideAgent(), conn.getClientSideRoute().getRouteLastHop());
			actions.add(factory.actions().output(conn.getClientSideRoute().getRouteLastHop().getPortId(), 0xffFFffFF));
		} else {
			log.debug("Sending server-side info packet to agent {} out switch+port {}", conn.getServerSideAgent(), conn.getServerSideRoute().getRouteLastHop());
			actions.add(factory.actions().output(conn.getServerSideRoute().getRouteLastHop().getPortId(), 0xffFFffFF));
		}
		ofPacket.setActions(actions);

		/* Put the UDP packet in the OF packet (encapsulate it as an OF packet) */
		byte[] udpPacket = l2.serialize();
		ofPacket.setData(udpPacket);

		/*
		 * Send the OF packet to the agent switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * UDP packet out the port specified.
		 */
		if (isClientSideAgent) {
			switchService.getSwitch(conn.getClientSideRoute().getRouteLastHop().getNodeId()).write(ofPacket.build());
		} else {
			switchService.getSwitch(conn.getServerSideRoute().getRouteLastHop().getNodeId()).write(ofPacket.build());
		}
	}

	/**
	 * Send an OF packet with the TCP "spark" packet (the packet that "sparked" the SOS session)
	 * encapsulated inside. This packet is destined for the client-side agent. 
	 * 
	 * @param l2, the Ethernet packet received by the SOS module.
	 * @param conn, The associated SOSConnection
	 */
	private void sendClientSideAgentSparkPacket(FloodlightContext cntx, Ethernet l2, SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getClientSideRoute().getRouteLastHop().getNodeId()).getOFFactory();

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* 
		 * L2 of packet
		 * Change the dst MAC to the client-side agent
		 */
		l2.setDestinationMACAddress(conn.getClientSideAgent().getMACAddr());

		/* 
		 * L3 of packet 
		 * Change the dst IP to the client-side agent
		 */
		IPv4 l3 = (IPv4) l2.getPayload();
		l3.setDestinationAddress(conn.getClientSideAgent().getIPAddr());

		/* 
		 * L4 of packet 
		 * Change destination TCP port to the one the agent is listening on
		 */
		TCP l4 = (TCP) l3.getPayload();
		l4.setDestinationPort(conn.getClientSideAgent().getDataPort());

		/* 
		 * Reconstruct the packet layer-by-layer 
		 */
		l3.setPayload(l4);
		l2.setPayload(l3);

		/* 
		 * Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		/* Output to the client-side agent -- this is the last hop of the route */
		actions.add(factory.actions().output(conn.getClientSideRoute().getRouteLastHop().getPortId(), 0xffFFffFF));
		ofPacket.setActions(actions);

		/* Put the TCP spark packet in the OF packet (encapsulate it as an OF packet) */
		ofPacket.setData(l2.serialize());

		/* 
		 * Send the OF packet to the agent switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * TCP packet out the port specified.
		 */
		switchService.getSwitch(conn.getClientSideRoute().getRouteLastHop().getNodeId()).write(ofPacket.build());
	}

	/**
	 * Send an OF packet with the TCP "spark" packet (the packet that "sparked" the SOS session)
	 * encapsulated inside. This packet is destined for the server from the server-side agent. 
	 * 
	 * @param l2, the Ethernet packet received by the SOS module.
	 * @param conn, The associated SOSConnection
	 */
	private void sendServerSparkPacket(FloodlightContext cntx, Ethernet l2, SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getServerSideRoute().getRouteFirstHop().getNodeId()).getOFFactory();

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* 
		 * L2 of packet
		 * Change the dst MAC to the server
		 */
		l2.setSourceMACAddress(conn.getClient().getMACAddr());

		/*
		 * L3 of packet 
		 * Change the dst IP to the server
		 */
		IPv4 l3 = (IPv4) l2.getPayload();
		l3.setSourceAddress(conn.getClient().getIPAddr());

		/*
		 * L4 of packet 
		 * Change source TCP port to the one the agent has opened
		 */
		TCP l4 = (TCP) l3.getPayload();
		l4.setSourcePort(conn.getServerSideAgentTcpPort());

		/* 
		 * Reconstruct the packet layer-by-layer 
		 */
		l3.setPayload(l4);
		l2.setPayload(l3);

		/* 
		 * Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		/* Output to the port facing the server -- route first hop is the server's AP */
		actions.add(factory.actions().output(conn.getServerSideRoute().getRouteFirstHop().getPortId(), 0xffFFffFF));
		ofPacket.setActions(actions);

		/* Put the TCP spark packet in the OF packet (encapsulate it as an OF packet) */
		ofPacket.setData(l2.serialize());

		/* 
		 * Send the OF packet to the switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * TCP packet out the port specified.
		 */
		switchService.getSwitch(conn.getServerSideRoute().getRouteFirstHop().getNodeId()).write(ofPacket.build());
	}

	/**
	 * Synchronized, since we don't want to have to worry about multiple connections starting up at the same time.
	 */
	@Override
	public synchronized net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		/*
		 * If we're disabled, then just stop now
		 * and let Forwarding/Hub handle the connection.
		 */
		if (!enabled) {
			log.trace("SOS disabled. Not acting on packet; passing to next module.");
			return Command.CONTINUE;
		} else {
			/*
			 * SOS is enabled; proceed
			 */
			log.trace("SOS enabled. Inspecting packet to see if it's a candidate for SOS.");
		}

		OFPacketIn pi = (OFPacketIn) msg;

		Ethernet l2 = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (l2.getEtherType() == EthType.IPv4) {
			log.debug("Got IPv4 Packet");

			IPv4 l3 = (IPv4) l2.getPayload();

			log.debug("Got IpProtocol {}", l3.getProtocol());

			if (l3.getProtocol().equals(IpProtocol.TCP)) {
				log.debug("Got TCP Packet on port " + (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? 
						pi.getInPort().toString() : 
							pi.getMatch().get(MatchField.IN_PORT).toString()) + " of switch " + sw.getId());

				TCP l4 = (TCP) l3.getPayload();
				/* 
				 * If this source IP and source port (or destination IP and destination port)
				 * have already been assigned a connection then we really shouldn't get to 
				 * this point. Flows matching the source IP and source port should have already
				 * been inserted switching those packets to the source agent. 
				 */

				/* Lookup the source IP address to see if it belongs to a client with a connection */
				log.debug("(" + l4.getSourcePort().toString() + ", " + l4.getDestinationPort().toString() + ")");

				SOSPacketStatus packetStatus = sosConnections.getSOSPacketStatus(
						l3.getSourceAddress(), l3.getDestinationAddress(),
						l4.getSourcePort(), l4.getDestinationPort()); 

				if (packetStatus == SOSPacketStatus.INACTIVE_REGISTERED){
					/* Process new TCP SOS session */
					log.info("Packet status was inactive but registered. Proceed with SOS.");

					IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);
					IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);

					if (srcDevice == null) {
						log.error("Source device was not known. Is DeviceManager running before SOS as it should? Report SOS bug.");
						return Command.STOP;
					} else {
						log.debug("Source device is {}", srcDevice);
					}
					if (dstDevice == null) {
						log.warn("Destination device was not known. ARPing for destination to try to learn it. Dropping TCP packet; TCP should keep retrying.");
						arpForDevice(l3.getDestinationAddress(), l3.getSourceAddress(), l2.getSourceMACAddress(), VlanVid.ofVlan(l2.getVlanID()), sw);
						return Command.STOP;
					} else {
						log.debug("Destination device is {}", dstDevice);
					}

					/* Init Agent/Client */
					SOSClient client = new SOSClient(l3.getSourceAddress(), l4.getSourcePort(), l2.getSourceMACAddress());
					SOSRoute clientRoute = routeToFriendlyNeighborhoodAgent(client, srcDevice.getAttachmentPoints(), IPv4Address.NONE);
					if (clientRoute == null) {
						log.error("Could not compute route from client {} to neighborhood agent. Report SOS bug.", client);
						for (SOSAgent agent : agents) {
							log.warn("Possibly lost agent {}. Emergency ARPing", agent);
							for (DatapathId dpid : switchService.getAllSwitchDpids()) {
								arpForDevice(
										agent.getIPAddr(), 
										(agent.getIPAddr().and(IPv4Address.of("255.255.255.0"))).or(IPv4Address.of("0.0.0.254")) /* Doesn't matter really; must be same subnet though */, 
										MacAddress.BROADCAST /* Use broadcast as to not potentially confuse a host's ARP cache */, 
										VlanVid.ZERO /* Switch will push correct VLAN tag if required */, 
										switchService.getSwitch(dpid)
										);
							}
						}
						return Command.STOP;
					} else {
						log.debug("Client-to-agent route {}", clientRoute);
					}

					/* Init Agent/Server */
					SOSServer server = new SOSServer(l3.getDestinationAddress(), l4.getDestinationPort(), l2.getDestinationMACAddress());
					SOSRoute serverRoute = routeToFriendlyNeighborhoodAgent(server, dstDevice.getAttachmentPoints(), 
							clientRoute.getRoute() != null ? clientRoute.getDstDevice().getIPAddr() : IPv4Address.NONE);
					if (serverRoute == null) {
						log.error("Could not compute route from server {} to neighborhood agent. Report SOS bug.", server);
						for (SOSAgent agent : agents) {
							log.warn("Possibly lost agent {}. Emergency ARPing", agent);
							for (DatapathId dpid : switchService.getAllSwitchDpids()) {
								arpForDevice(
										agent.getIPAddr(), 
										(agent.getIPAddr().and(IPv4Address.of("255.255.255.0"))).or(IPv4Address.of("0.0.0.254")) /* Doesn't matter really; must be same subnet though */, 
										MacAddress.BROADCAST /* Use broadcast as to not potentially confuse a host's ARP cache */, 
										VlanVid.ZERO /* Switch will push correct VLAN tag if required */, 
										switchService.getSwitch(dpid)
										);
							}
						}
						return Command.STOP;
					} else {
						log.debug("Server-to-agent route {}", serverRoute);
					}

					SOSRoute interAgentRoute = routeBetweenAgents((SOSAgent) clientRoute.getDstDevice(), (SOSAgent) serverRoute.getDstDevice());
					if (interAgentRoute == null) {
						log.error("Could not compute route from agent {} to agent {}. Report SOS bug.", (SOSAgent) clientRoute.getDstDevice(), (SOSAgent) serverRoute.getDstDevice());
						return Command.STOP;
					} else {
						log.debug("Inter-agent route {}", interAgentRoute);
					}

					/* Establish connection */
					SOSConnection newSOSconnection = sosConnections.addConnection(clientRoute, interAgentRoute, serverRoute, 
							agentNumParallelSockets, agentQueueCapacity, bufferSize, flowTimeout);
					log.debug("Starting new SOS session: \r\n" + newSOSconnection.toString());

					/* Send UDP messages to the home and foreign agents */
					log.debug("Sending UDP information packets to client-side and server-side agents");
					sendInfoToAgent(cntx, newSOSconnection, true); /* home */
					sendInfoToAgent(cntx, newSOSconnection, false); /* foreign */
					
					/* Push flows and add flow names to connection (for removal upon termination) */
					log.debug("Pushing client-side SOS flows");
					pushRoute(newSOSconnection.getClientSideRoute(), newSOSconnection);
					log.debug("Pushing inter-agent SOS flows");
					pushRoute(newSOSconnection.getInterAgentRoute(), newSOSconnection);

					/* Send the initial TCP packet that triggered this module to the home agent */
					log.debug("Sending client-side spark packet to client-side agent");
					sendClientSideAgentSparkPacket(cntx, l2, newSOSconnection);

				} else if (packetStatus == SOSPacketStatus.ACTIVE_SERVER_SIDE_AGENT_TO_SERVER) {					
					SOSConnection conn = sosConnections.getConnection(l3.getDestinationAddress(), l4.getDestinationPort());

					if (conn == null) {
						log.error("Should have found an SOSConnection in need of a server-side agent TCP port!");
					} else {
						conn.setServerSideAgentTcpPort(l4.getSourcePort());
						log.debug("Finalizing SOS session: \r\n" + conn.toString());

						log.debug("Pushing server-side SOS flows");
						pushRoute(conn.getServerSideRoute(), conn);

						log.debug("Sending server-side spark packet to server");
						sendServerSparkPacket(cntx, l2, conn);
					}
				} else if (packetStatus == SOSPacketStatus.INACTIVE_UNREGISTERED) {
					log.warn("Received an unregistered TCP packet. Register the connection to have it operated on by SOS.");
					return Command.CONTINUE; /* Short circuit default return for unregistered -- let Forwarding/Hub handle it */
				} else {
					log.error("Received a TCP packet w/status {} that belongs to an ongoing SOS session. Check accuracy of flows/Report SOS bug", packetStatus);
				}

				/* We don't want other modules messing with our SOS TCP session (namely Forwarding/Hub) */
				return Command.STOP;

			} /* END IF TCP packet */
			else if (l3.getProtocol().equals(IpProtocol.UDP)) {
				UDP l4 = (UDP) l3.getPayload();

				for (SOSAgent agent : agents) {
					if (agent.getIPAddr().equals(l3.getSourceAddress()) /* FROM known agent */
							&& agent.getFeedbackPort().equals(l4.getDestinationPort())) { /* TO our feedback port */
						UUID uuid = UUID.fromString(new String(((Data) l4.getPayload()).getData() /* TODO , "ASCII-US or UTF-8?" */)); 
						log.debug("Got termination message from agent {} for UUID {}", agent.getIPAddr(), uuid);

						SOSConnection conn = sosConnections.getConnection(uuid);
						if (conn == null) {
							log.error("Could not locate UUID {} in connection storage. Report SOS bug", uuid);
							return Command.STOP; /* this WAS for us, but there was an error; no need to forward */
						}

						/* We found it; remove flows; delete from storage */
						for (String flowName : conn.getFlowNames()) {
							log.trace("Deleting flow {}", flowName);
							sfp.deleteFlow(flowName);
						}

						log.warn("Removing expired connection {}", uuid);
						sosConnections.removeConnection(uuid);
						break;
					}
				} /* END FROM-AGENT LOOKUP */
			} /* END IF UDP packet */
		} /* END IF IPv4 packet */
		return Command.CONTINUE;
	} /* END of receive(pkt) */

	/**
	 * Lookup an agent based on the client's current location. Shortest path
	 * routing is used to determine the closest agent. The route is returned
	 * inclusive of the SOS agent.
	 * 
	 * Lookup can be done for either client or server of a TCP connection. 
	 * Supply the IP address of a previously determined agent to select a 
	 * different agent in the event both clients result in the same agent 
	 * being selected.
	 * 
	 * @param dev, either client or server
	 * @param agentToAvoid, optional, use IPv4Address.NONE if N/A
	 * @return
	 */
	private SOSRoute routeToFriendlyNeighborhoodAgent(SOSDevice dev, SwitchPort[] devAps, IPv4Address agentToAvoid) {
		Route shortestPath = null;
		SOSAgent closestAgent = null;

		/* First, make sure client has a valid attachment point */
		if (devAps.length == 0) {
			log.warn("Client/Server {} was found in the device manager but does not have a valid attachment point. Report SOS bug.");
			return null;
		}
		/* Then, narrow down the APs to the real location where the device is connected */
		SwitchPort devTrueAp = findTrueAttachmentPoint(devAps);
		if (devTrueAp == null) {
			log.error("Could not determine true attachment point for device {}. Report SOS bug.", dev);
			return null;
		}

		for (SOSAgent agent : agents) {
			/* Skip agent earmarked for other client */
			if (agent.getIPAddr().equals(agentToAvoid)) {
				log.debug("Skipping earmarked agent {}", agent);
			} else {
				/* Find where the agent is attached. Only *ONE* device should be returned here, ever. Assume 0th device is the correct one. */
				Iterator<? extends IDevice> i = deviceService.queryDevices(MacAddress.NONE, null, agent.getIPAddr(), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
				if (i.hasNext()) {
					IDevice d = i.next();
					SwitchPort[] agentAps = d.getAttachmentPoints();
					if (agentAps.length > 0) {
						SwitchPort agentTrueAp = findTrueAttachmentPoint(agentAps);
						if (agentTrueAp == null) {
							log.error("Could not determine true attachment point for agent {}. Trying next agent. Report SOS bug.", agent);
							continue;
						}
						log.trace("Asking for route from {} to {}", devTrueAp, agentTrueAp);
						Route r = routingService.getRoute(devTrueAp.getSwitchDPID(), devTrueAp.getPort(), agentTrueAp.getSwitchDPID(), agentTrueAp.getPort(), U64.ZERO);
						if (r != null && shortestPath == null) {
							log.debug("Found initial agent {} w/route {}", agent, r);
							shortestPath = r;
							closestAgent = agent;
							closestAgent.setMACAddr(d.getMACAddress()); /* set the MAC while we're here; TODO listen for device updates from IDeviceListener instead */
						} else if (r != null && shortestPath.getPath().size() > r.getPath().size()) { /* This implies we keep the first agent if there's a tie */
							if (log.isDebugEnabled()) { /* Use isDebugEnabled() when we have to create a new object for the log */
								log.debug("Found new agent {} w/shorter route. Old route {}; new route {}", new Object[] { agent, shortestPath, r});
							}
							shortestPath = r;
							closestAgent = agent;
							closestAgent.setMACAddr(d.getMACAddress()); /* set the MAC while we're here; TODO listen for device updates from IDeviceListener instead */
						} else {
							if (log.isDebugEnabled()) { 
								log.debug("Retaining current agent {} w/shortest route. Kept route {}; Longer contender {}, {}", new Object[] { closestAgent, shortestPath, agent, r }); 
							}
						}
					} else {
						log.debug("Agent {} was located but did not have any valid attachment points", agent);
					}

				} else {
					log.debug("Query for agents with IP address of {} resulted in no devices. Trying other agents.", agent);
				}
			}
		}

		/* If we get here, we should have iterated through all agents for the closest */
		if (closestAgent == null) {
			log.error("Could not find a path from client/server {} to any agent {}. Report SOS bug.", dev, agents);
			return null;
		} else {
			log.debug("Agent {} was found closest to client/server {}", closestAgent, dev);
		}

		return new SOSRoute(dev, closestAgent, shortestPath);
	}

	/**
	 * A "true" attachment point is defined as the physical location
	 * in the network where the device is plugged in.
	 * 
	 * Each OpenFlow island can have up to exactly one attachment point 
	 * per device. If there are multiple islands and the same device is 
	 * known on each island, then there must be a link between these 
	 * islands (assuming no devices with duplicate MACs exist). If there
	 * is no link between the islands, then the device cannot be learned
	 * on each island (again, assuming all devices have unique MACs).
	 * 
	 * This means if we iterate through the attachment points and find
	 * one who's switch port is not a member of a link b/t switches/islands,
	 * then that attachment point is the device's true location. All other
	 * attachment points are where the device is known on other islands and
	 * should reside on external/iter-island links.
	 * 
	 * @param aps
	 * @return
	 */
	private SwitchPort findTrueAttachmentPoint(SwitchPort[] aps) {
		if (aps != null) {
			for (SwitchPort ap : aps) {
				Set<OFPort> portsOnLinks = topologyService.getPortsWithLinks(ap.getSwitchDPID());
				if (portsOnLinks == null) {
					log.error("Error looking up ports with links from topology service for switch {}", ap.getSwitchDPID());
					continue;
				}
				
				if (!portsOnLinks.contains(ap.getPort())) {
					log.debug("Found 'true' attachment point of {}", ap);
					return ap;
				} else {
					log.trace("Attachment point {} was not the 'true' attachment point", ap);
				}
			}
		}
		/* This will catch case aps=null, empty, or no-true-ap */
		log.error("Could not locate a 'true' attachment point in {}", aps);
		return null;
	}

	/**
	 * Find the shortest route (by hop-count) between two SOS agents. 
	 * Do not push flows for the route.
	 * @param src
	 * @param dst
	 * @return
	 */
	private SOSRoute routeBetweenAgents(SOSAgent src, SOSAgent dst) {

		/* Find where the agent is attached. Only *ONE* device should be returned here, ever. Assume 0th device is the correct one. */
		Iterator<? extends IDevice> si = deviceService.queryDevices(MacAddress.NONE, null, src.getIPAddr(), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
		Iterator<? extends IDevice> di = deviceService.queryDevices(MacAddress.NONE, null, dst.getIPAddr(), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);

		if (si.hasNext() && di.hasNext()) {
			IDevice sd = si.next();
			IDevice dd = di.next();

			SwitchPort sTrueAp = findTrueAttachmentPoint(sd.getAttachmentPoints());
			SwitchPort dTrueAp = findTrueAttachmentPoint(dd.getAttachmentPoints());
			if (sTrueAp == null) {
				log.error("Could not locate true attachment point for client-side agent {}. APs were {}. Report SOS bug.", src, sd.getAttachmentPoints());
				return null;
			} else if (dTrueAp == null) {
				log.error("Could not locate true attachment point for server-side agent {}. APs were {}. Report SOS bug.", dst, dd.getAttachmentPoints());
				return null;
			}


			Route r = routingService.getRoute(sTrueAp.getSwitchDPID(), sTrueAp.getPort(), dTrueAp.getSwitchDPID(), dTrueAp.getPort(), U64.ZERO);
			if (r == null) {
				log.error("Could not find route between {} at AP {} and {} at AP {}", new Object[] { src, sTrueAp, dst, dTrueAp});
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Between agent {} and agent {}, found route {}", new Object[] {src, dst, r});
				}
				return new SOSRoute(src, dst, r);
			}
		} else {
			log.debug("Query for agents resulted in no devices. Source iterator: {}; Destination iterator {}", si, di);
		}
		return null;
	}

	/**
	 * Try to force-learn a device that the device manager does not know
	 * about already. The ARP reply (we hope for) will trigger learning
	 * the new device, and the next TCP SYN we receive after that will
	 * result in a successful device lookup in the device manager.
	 * @param dstIp
	 * @param srcIp
	 * @param srcMac
	 * @param vlan
	 * @param sw
	 */
	private void arpForDevice(IPv4Address dstIp, IPv4Address srcIp, MacAddress srcMac, VlanVid vlan, IOFSwitch sw) {
		IPacket arpRequest = new Ethernet()
		.setSourceMACAddress(srcMac)
		.setDestinationMACAddress(MacAddress.BROADCAST)
		.setEtherType(EthType.ARP)
		.setVlanID(vlan.getVlan())
		.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REQUEST)
				.setSenderHardwareAddress(srcMac)
				.setSenderProtocolAddress(srcIp)
				.setTargetHardwareAddress(MacAddress.NONE)
				.setTargetProtocolAddress(dstIp));

		OFPacketOut po = sw.getOFFactory().buildPacketOut()
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))
				.setBufferId(OFBufferId.NO_BUFFER)
				.setData(arpRequest.serialize())
				.setInPort(OFPort.CONTROLLER)
				.build();
		sw.write(po);
	}

	/**
	 * Push flows required for the route provided. If the route is only a single
	 * hop, we assume the single switch is capable of performing all necessary
	 * L2, L3, and L4 header rewrites. More importantly, if the route is more
	 * than two hops, we assume the first hop will perform the redirection of
	 * TCP packets to/from the agent and rewrite L2 headers, while the last hop 
	 * will rewrite the L3 and L4 headers. This algorithm is chosen to support
	 * a common configuration where OVS is used as the last hop right before
	 * an agent to supplement the lack of higher layer header rewrite support
	 * in prior-hop physical OpenFlow switches.
	 * 
	 * TODO use table features (OF1.3) to determine what each switch can do.
	 * 
	 * @param route
	 */
	private void pushRoute(SOSRoute route, SOSConnection conn) {
		ISOSRoutingStrategy rs;
		if (route.getRouteType() == SOSRouteType.CLIENT_2_AGENT) {
			rs = new SOSRoutingStrategyFirstHopLastHop(true);
			rs.pushRoute(route, conn);
		} else if (route.getRouteType() == SOSRouteType.AGENT_2_AGENT) {
			rs = new SOSRoutingStrategyInterAgent();
			rs.pushRoute(route, conn);
		} else if (route.getRouteType() == SOSRouteType.SERVER_2_AGENT) {
			rs = new SOSRoutingStrategyFirstHopLastHop(true);
			rs.pushRoute(route, conn);
		} else {
			log.error("Received invalid SOSRouteType of {}", route.getRouteType());
		}
	}

	/* **********************************
	 * IOFSwitchListener implementation *
	 * **********************************/

	@Override
	public void switchAdded(DatapathId dpid) {
	}

	@Override
	public void switchRemoved(DatapathId dpid) {
	}

	@Override
	public void switchPortChanged(DatapathId dpid, OFPortDesc portDesc, PortChangeType portChangeType) {
	}

	@Override
	public void switchActivated(DatapathId switchId) {
	}

	@Override
	public void switchChanged(DatapathId switchId) {
	}

	/* ****************************
	 * ISOSService implementation *
	 * ****************************/

	@Override
	public synchronized SOSReturnCode addAgent(SOSAgent agent) {
		if (agents.contains(agent)) { /* MACs are ignored in devices for equality check, so we should only compare IP and ports here */
			log.error("Found pre-existing agent during agent add. Not adding new agent {}", agent);
			return SOSReturnCode.ERR_DUPLICATE_AGENT;
		} else {
			if (agents.add(agent)) { 
				log.warn("Agent {} added.", agent);
			} else {
				log.error("Error. Agent {} NOT added.", agent);
			}
			Set<DatapathId> switches = switchService.getAllSwitchDpids();
			for (DatapathId sw : switches) {
				log.debug("ARPing for agent {} on switch {}", agent, sw);
				arpForDevice(
						agent.getIPAddr(), 
						(agent.getIPAddr().and(IPv4Address.of("255.255.255.0"))).or(IPv4Address.of("0.0.0.254")) /* Doesn't matter really; must be same subnet though */, 
						MacAddress.BROADCAST /* Use broadcast as to not potentially confuse a host's ARP cache */, 
						VlanVid.ZERO /* Switch will push correct VLAN tag if required */, 
						switchService.getSwitch(sw)
						);
			}

			if (agentMonitor == null) {
				log.warn("Configuring agent ARP monitor thread");
				agentMonitor = threadPoolService.getScheduledExecutor().scheduleAtFixedRate(
						new SOSAgentMonitor(), 
						/* initial delay */ 20, 
						/* interval */ 15, 
						TimeUnit.SECONDS);
			}

			return SOSReturnCode.AGENT_ADDED;
		}
	}

	@Override
	public synchronized SOSReturnCode removeAgent(SOSAgent agent) {
		if (agents.contains(agent)) { /* MACs are ignored in devices for equality check, so we should only compare IP and ports here */
			agents.remove(agent);
			log.warn("Agent {} removed.", agent);
			return SOSReturnCode.AGENT_REMOVED;
		} else {
			log.error("Could not locate agent {} to remove. Not removing agent.", agent);
			return SOSReturnCode.ERR_UNKNOWN_AGENT;
		}
	}

	@Override
	public synchronized SOSReturnCode addWhitelistEntry(SOSWhitelistEntry entry) {
		return sosConnections.addWhitelistEntry(entry);
	}

	@Override
	public synchronized SOSReturnCode removeWhitelistEntry(SOSWhitelistEntry entry) {
		return sosConnections.removeWhitelistEntry(entry);
	}

	@Override
	public synchronized SOSReturnCode enable() {
		log.warn("Enabling SOS");
		enabled = true;
		return SOSReturnCode.ENABLED;
	}

	@Override
	public synchronized SOSReturnCode disable() {
		log.warn("Disabling SOS");
		enabled = false;
		return SOSReturnCode.DISABLED;
	}

	@Override
	public SOSStatistics getStatistics() {
		log.error("Statistics not implemented");
		// TODO Implement statistics
		return null;
	}

	@Override
	public synchronized SOSReturnCode setFlowTimeouts(int hardSeconds, int idleSeconds) {
		if (idleSeconds >= 0) {
			flowTimeout = (short) idleSeconds;
			log.warn("Set idle timeout to {}. Ignoring hard timeout of {}", idleSeconds, hardSeconds);
		}
		return SOSReturnCode.CONFIG_SET;
	}

	@Override
	public synchronized SOSReturnCode setNumParallelConnections(int num) {
		agentNumParallelSockets = num;
		log.warn("Set number of parallel connections to {}", num);
		return SOSReturnCode.CONFIG_SET;
	}

	@Override
	public synchronized SOSReturnCode setBufferSize(int bytes) {
		bufferSize = bytes;
		return SOSReturnCode.CONFIG_SET;
	}

	@Override
	public synchronized SOSReturnCode setQueueCapacity(int packets) {
		agentQueueCapacity = packets;
		return SOSReturnCode.CONFIG_SET;
	}
}