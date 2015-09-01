package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.match.Match;
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
import org.projectfloodlight.openflow.types.TransportPort;
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
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;

/**
 * Steroid OpenFlow Service Module
 * @author Ryan Izard, rizard@g.clemson.edu
 * 
 */
public class SOS implements IOFMessageListener, IOFSwitchListener, IFloodlightModule  {
	private static final Logger log = LoggerFactory.getLogger(SOS.class);
	private static IFloodlightProviderService floodlightProvider;
	private static IOFSwitchService switchService;
	private static ITopologyService topologyService;
	private static IRoutingService routingService;
	private static IDeviceService deviceService;
	private static IStaticFlowEntryPusherService sfp;

	private static MacAddress controllerMac;
	private static TransportPort agentControlPort; // 9998
	private static TransportPort agentDataPort; // 9877

	private static SOSConnections sosConnections;
	private static Set<SOSAgent> agents;

	private static int bufferSize;
	private static int agentQueueCapacity;
	private static int agentNumParallelSockets;
	private static short flowTimeout;

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		routingService = context.getServiceImpl(IRoutingService.class);
		topologyService = context.getServiceImpl(ITopologyService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);

		agents = new HashSet<SOSAgent>();
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);

		// Read our config options
		Map<String, String> configOptions = context.getConfigParams(this);
		try {
			controllerMac = MacAddress.of(configOptions.get("controller-mac"));

			bufferSize = Integer.parseInt(configOptions.get("buffer-size"));
			agentQueueCapacity = Integer.parseInt(configOptions.get("queue-capacity"));
			agentNumParallelSockets = Integer.parseInt(configOptions.get("parallel-tcp-sockets"));
			flowTimeout = Short.parseShort(configOptions.get("flow-timeout"));

			agentControlPort = TransportPort.of(Integer.parseInt(configOptions.get("agent-msg-port")));
			agentDataPort = TransportPort.of(Integer.parseInt(configOptions.get("agent-tcp-port")));

		} catch(IllegalArgumentException ex) {
			log.error("Incorrect SOS configuration options", ex);
			throw ex;
		} catch(NullPointerException ex) {
			log.error("Incorrect SOS configuration options", ex);
			throw ex;
		}

		sosConnections = new SOSConnections();
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public String getName() {
		return SOS.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Allow the CONTEXT_SRC/DST_DEVICE field to be populated by the DeviceManager. This makes our job easier :)
		if (type == OFType.PACKET_IN && name.equalsIgnoreCase("devicemananger")) {
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

		/* L3 of packet */
		IPv4 l3 = new IPv4();
		l3.setSourceAddress(isClientSideAgent ? conn.getServerSideAgent().getIPAddr() : conn.getServer().getIPAddr());
		l3.setDestinationAddress(isClientSideAgent ? conn.getClientSideAgent().getIPAddr() : conn.getServerSideAgent().getIPAddr());
		l3.setProtocol(IpProtocol.UDP);
		l3.setTtl((byte) 64);

		/* L4 of packet */
		UDP l4 = new UDP();
		l4.setSourcePort(conn.getServer().getTcpPort());
		l4.setDestinationPort(isClientSideAgent ? conn.getClientSideAgent().getControlPort() : conn.getServerSideAgent().getControlPort());


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
			actions.add(factory.actions().output(conn.getClientSideRoute().getRouteLastHop().getPortId(), 0xffFFffFF));
		} else {
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

		OFPacketIn pi = (OFPacketIn) msg;

		Ethernet l2 = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (l2.getEtherType() == EthType.IPv4) {
			log.debug("Got IPv4 Packet");

			IPv4 l3 = (IPv4) l2.getPayload();

			log.debug("Got IpProtocol {}", l3.getProtocol());

			if (l3.getProtocol().equals(IpProtocol.TCP)) {
				log.debug("Got TCP Packet on port " + (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort().toString() : pi.getMatch().get(MatchField.IN_PORT).toString()) + " of switch " + sw.getId());
				TCP l4 = (TCP) l3.getPayload();
				/* If this source IP and source port (or destination IP and destination port)
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

					/* Init Source Agent/Client */
					SOSClient client = new SOSClient(l3.getSourceAddress(), l4.getSourcePort(), l2.getSourceMACAddress());
					SOSRoute clientRoute = routeToNeighborhoodAgent(client, srcDevice.getAttachmentPoints(), IPv4Address.NONE);
					if (clientRoute == null) {
						return Command.STOP;
					}

					/* Init Agent/Server */
					SOSServer server = new SOSServer(l3.getDestinationAddress(), l4.getDestinationPort(), l2.getDestinationMACAddress());
					SOSRoute serverRoute = routeToNeighborhoodAgent(server, dstDevice.getAttachmentPoints(), 
							clientRoute.getRoute() != null ? clientRoute.getDstDevice().getIPAddr() : IPv4Address.NONE);
					if (serverRoute == null) {
						return Command.STOP;
					}
					
					SOSRoute interAgentRoute = routeBetweenAgents((SOSAgent) clientRoute.getDstDevice(), (SOSAgent) clientRoute.getDstDevice());

					/* Establish connection */
					SOSConnection newSOSconnection = sosConnections.addConnection(clientRoute, interAgentRoute, serverRoute, 
							agentNumParallelSockets, agentQueueCapacity, bufferSize);
					log.debug("Starting new SOS session: \r\n" + newSOSconnection.toString());

					/* Push flows and add flow names to connection (for removal upon termination) */
					log.debug("Pushing source-side and inter-agent SOS flows");
					pushRoute(newSOSconnection.getClientSideRoute());
					pushRoute(newSOSconnection.getInterAgentRoute());
					
					/*
					pushSOSFlow_1(newSOSconnection);                                 
					pushSOSFlow_2(newSOSconnection);
					pushSOSFlow_3(newSOSconnection);
					pushSOSFlow_4(newSOSconnection);
					pushSOSFlow_5(newSOSconnection);
					//pushSOSFlow_6(newSOSconnection);
					pushSOSFlow_6a(newSOSconnection);
					pushSOSFlow_6b(newSOSconnection);
					pushSOSFlow_7(newSOSconnection);
					pushSOSFlow_8(newSOSconnection);
					//pushSOSFlow_9(newSOSconnection);
					pushSOSFlow_9a(newSOSconnection);
					pushSOSFlow_9b(newSOSconnection);
					pushSOSFlow_10(newSOSconnection);
					*/

					/* Send the initial TCP packet that triggered this module to the home agent */
					log.debug("Sending client-side spark packet to client-side agent");
					sendClientSideAgentSparkPacket(cntx, l2, newSOSconnection);

					/* Send UDP messages to the home and foreign agents */
					log.debug("Sending UDP information packets to client-side and server-side agents");
					sendInfoToAgent(cntx, newSOSconnection, true); // home
					sendInfoToAgent(cntx, newSOSconnection, false); // foreign

				} else if (packetStatus == SOSPacketStatus.ACTIVE_SERVER_SIDE_AGENT_TO_SERVER) {					
					SOSConnection conn = sosConnections.getConnectionFromIP(l3.getDestinationAddress(), l4.getDestinationPort());

					if (conn == null) {
						log.error("Should have found an SOSConnection in need of a server-side agent TCP port!");
					} else {
						conn.setServerSideAgentTcpPort(l4.getSourcePort());
						log.debug("Finalizing SOS session: \r\n" + conn.toString());

						log.debug("Pushing server-side SOS flows");
						pushRoute(conn.getServerSideRoute());
						
						/*
						pushSOSFlow_11(conn);
						pushSOSFlow_12(conn);
						pushSOSFlow_13(conn);
						pushSOSFlow_14(conn);
						*/

						log.debug("Sending server-side spark packet to server");
						sendServerSparkPacket(cntx, l2, conn);
					}
				} else if (packetStatus == SOSPacketStatus.INACTIVE_UNREGISTERED) {
					log.warn("Received an unregistered TCP packet. Register the connection to have it operated on by SOS.");
					return Command.CONTINUE; /* Short circuit default return for unregistered -- let Forwarding/Hub handle it */
				} else {
					log.error("Received a TCP packet w/status {} that belongs to an ongoing SOS session. Check accuracy of flows/Report SOS bug", packetStatus);
				}

				/* We don't want other modules messing with our SOS TCP session (namely Forwarding) */
				return Command.STOP;

			} // END IF TCP packet
		} // END IF IPv4 packet
		return Command.CONTINUE;
	} // END of receive(pkt)

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
	private SOSRoute routeToNeighborhoodAgent(SOSDevice dev, SwitchPort[] devAps, IPv4Address agentToAvoid) {
		Route shortestPath = null;
		SOSAgent closestAgent = null;

		/* First, make sure client has a valid attachment point */
		if (devAps.length == 0) {
			log.warn("Client/Server {} was found in the device manager but does not have a valid attachment point. Report SOS bug.");
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
					/* The 0th attachment point should always be the real location unless we've experienced an agent migration (which should be done in a maintenance period). */
					SwitchPort[] agentAps = d.getAttachmentPoints();
					if (agentAps.length > 0) {
						Route r = routingService.getRoute(devAps[0].getSwitchDPID(), agentAps[0].getSwitchDPID(), U64.ZERO);
						if (shortestPath == null) {
							log.debug("Found initial agent {} w/route {}", agent, r);
							shortestPath = r;
							closestAgent = agent;
						} else if (shortestPath.getRouteCount() > r.getRouteCount()) {
							if (log.isDebugEnabled()) { /* Use isDebugEnabled() when we have to create a new object for the log */
								log.debug("Found new agent {} w/shorter route. Old route {}; new route {}", new Object[] { agent, shortestPath, r});
							}
							shortestPath = r;
							closestAgent = agent;
						} else {
							if (log.isDebugEnabled()) { 
								log.debug("Retaining current agent {} w/shortest route. Kept route {}; Longer contender {}", new Object[] { agent, shortestPath, r }); 
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
		}

		return new SOSRoute(dev, closestAgent, shortestPath);
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
			
			/* The 0th attachment point should always be the real location unless we've experienced an agent migration (which should be done in a maintenance period). */
			SwitchPort[] sAps = sd.getAttachmentPoints();
			SwitchPort[] dAps = dd.getAttachmentPoints();

			if (sAps.length > 0 && dAps.length > 0) {
				Route r = routingService.getRoute(sAps[0].getSwitchDPID(), dAps[0].getSwitchDPID(), U64.ZERO);
				if (r == null) {
					log.error("Could not find route between {} at AP {} and {} at AP {}", new Object[] { src, sAps, dst, dAps});
				} else {
					return new SOSRoute(src, dst, r);
				}
			} else {
				log.error("Agent had no APs. {} at AP {} and {} at AP {}", new Object[] { src, sAps, dst, dAps});
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

	private void pushRoute(SOSRoute route) {
		if (route.getRouteType() == SOSRouteType.CLIENT_2_AGENT) {
			
		} else if (route.getRouteType() == SOSRouteType.AGENT_2_AGENT) {
			
		} else if (route.getRouteType() == SOSRouteType.SERVER_2_AGENT) {
			
		} else {
			log.error("Received invalid SOSRouteType of {}", route.getRouteType());
		}
	}
	
	public void pushSOSFlow_1(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getSrcClient().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getSrcClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_SRC, conn.getSrcPort());

		if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
			actionList.add(factory.actions().setDlDst(conn.getSrcAgent().getMACAddr()));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethDst(conn.getSrcAgent().getMACAddr())));
		}

		actionList.add(factory.actions().output(conn.getSrcAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-1-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcNtwkSwitch()).getId() + flowName);
	}
	public void pushSOSFlow_2(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, SRC_AGENT_OVS_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getSrcClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_SRC, conn.getSrcPort());

		if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
			actionList.add(factory.actions().setDlDst(conn.getSrcAgent().getMACAddr()));
			actionList.add(factory.actions().setNwDst(conn.getSrcAgent().getIPAddr()));
			actionList.add(factory.actions().setTpDst(agentDataPort));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethDst(conn.getSrcAgent().getMACAddr())));
			actionList.add(factory.actions().setField(factory.oxms().ipv4Dst(conn.getSrcAgent().getIPAddr())));
			actionList.add(factory.actions().setField(factory.oxms().tcpDst(agentDataPort)));
		}

		actionList.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-2-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcAgentSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_3(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.LOCAL);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_DST, conn.getSrcPort());

		if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
			actionList.add(factory.actions().setDlSrc(conn.getDstClient().getMACAddr()));
			actionList.add(factory.actions().setNwSrc(conn.getDstClient().getIPAddr()));
			actionList.add(factory.actions().setTpSrc(conn.getDstPort()));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getDstClient().getMACAddr())));
			actionList.add(factory.actions().setField(factory.oxms().ipv4Src(conn.getDstClient().getIPAddr())));
			actionList.add(factory.actions().setField(factory.oxms().tcpSrc(conn.getDstPort())));
		}

		actionList.add(factory.actions().output(SRC_AGENT_OVS_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-3-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcAgentSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_4(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getSrcAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_DST, conn.getSrcPort());

		/*dlsrcAction.setType(OFActionType.SET_DL_SRC);
		dlsrcAction.setDataLayerAddress(conn.getDstClient().getMACAddr());
		dlsrcAction.setLength((short) OFActionDataLayerSource.MINIMUM_LENGTH);
		actionList.add(dlsrcAction); */

		actionList.add(factory.actions().output(conn.getSrcClient().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-4-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_5(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.LOCAL);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstAgent().getIPAddr()); 
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(SRC_AGENT_OVS_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-5-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcAgentSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_6(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getSrcAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(conn.getDstAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-6-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_6a(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getSrcAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(SRC_NTWK_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-6a-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_6b(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, DST_NTWK_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(conn.getDstAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-6b-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_7(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, DST_AGENT_OVS_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getSrcAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-7-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstAgentSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_8(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.LOCAL);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(DST_AGENT_OVS_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-8-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstAgentSwitch()).getId() + flowName);
	} 

	public void pushSOSFlow_9(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getDstAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(conn.getSrcAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-d9-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_9a(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getDstAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(DST_NTWK_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-9a-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_9b(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, SRC_NTWK_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getSrcAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(conn.getSrcAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-9b-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcNtwkSwitch()).getId() + flowName);
	}


	public void pushSOSFlow_10(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getSrcAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, SRC_AGENT_OVS_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getDstAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-10-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getSrcAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getSrcAgentSwitch()).getId() + flowName);
	} 

	public void pushSOSFlow_11(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.LOCAL);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstClient().getIPAddr());
		match.setExact(MatchField.TCP_DST, conn.getDstPort());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);

		if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
			actionList.add(factory.actions().setDlSrc(conn.getSrcClient().getMACAddr()));
			actionList.add(factory.actions().setNwSrc(conn.getSrcClient().getIPAddr()));
			actionList.add(factory.actions().setTpSrc(conn.getSrcPort()));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getSrcClient().getMACAddr())));
			actionList.add(factory.actions().setField(factory.oxms().ipv4Src(conn.getSrcClient().getIPAddr())));
			actionList.add(factory.actions().setField(factory.oxms().tcpSrc(conn.getSrcPort())));
		}

		actionList.add(factory.actions().output(DST_AGENT_OVS_PORT, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-11-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstAgentSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_12(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getDstAgent().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_DST, conn.getDstClient().getIPAddr());
		match.setExact(MatchField.TCP_DST, conn.getDstPort());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);

		/*dlsrcAction.setType(OFActionType.SET_DL_SRC);
		dlsrcAction.setDataLayerAddress(conn.getSrcClient().getMACAddr());
		dlsrcAction.setLength((short) OFActionDataLayerSource.MINIMUM_LENGTH);
		actionList.add(dlsrcAction); */

		actionList.add(factory.actions().output(conn.getDstClient().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-12-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_13(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstNtwkSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, conn.getDstClient().getSwitchPort());
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getDstClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_SRC, conn.getDstPort());

		/*dldestAction.setType(OFActionType.SET_DL_DST);
		dldestAction.setDataLayerAddress(conn.getDstAgent().getMACAddr());
		dldestAction.setLength((short) OFActionDataLayerDestination.MINIMUM_LENGTH);
		actionList.add(dldestAction);*/

		actionList.add(factory.actions().output(conn.getDstAgent().getSwitchPort(), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-13-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstNtwkSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstNtwkSwitch()).getId() + flowName);
	}

	public void pushSOSFlow_14(SOSConnection conn) {
		OFFactory factory = switchService.getSwitch(conn.getDstAgentSwitch()).getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, DST_AGENT_OVS_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getDstClient().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		match.setExact(MatchField.TCP_SRC, conn.getDstPort());

		if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
			actionList.add(factory.actions().setDlDst(conn.getDstAgent().getMACAddr()));
			actionList.add(factory.actions().setNwDst(conn.getDstAgent().getIPAddr()));
			actionList.add(factory.actions().setTpDst(conn.getDstAgentL4Port()));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethDst(conn.getDstAgent().getMACAddr())));
			actionList.add(factory.actions().setField(factory.oxms().ipv4Dst(conn.getDstAgent().getIPAddr())));
			actionList.add(factory.actions().setField(factory.oxms().tcpDst(conn.getDstAgentL4Port())));
		}

		actionList.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(flowTimeout);

		String flowName = "sos-14-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), switchService.getSwitch(conn.getDstAgentSwitch()).getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + switchService.getSwitch(conn.getDstAgentSwitch()).getId() + flowName);
	}	



	@Override
	public void switchAdded(DatapathId dpid) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		// For now, let's assume we have two DPIDs as in our config file.
		if (SRC_NTWK_SWITCH_DPID.equals(sw.getId())) {
			SRC_NTWK_SWITCH = new SOSSwitch(sw);
			SRC_NTWK_SWITCH.addClient(SRC_CLIENT);
			SRC_NTWK_SWITCH.setLocalAgent(SRC_AGENT);
			log.debug("Source NTWK switch set and configured!");
		}
		// Not an else-if... we may want two agents on a single switch for whatever reason
		if (DST_NTWK_SWITCH_DPID.equals(sw.getId())) {
			DST_NTWK_SWITCH = new SOSSwitch(sw);
			DST_NTWK_SWITCH.addClient(DST_CLIENT);
			DST_NTWK_SWITCH.setLocalAgent(DST_AGENT);
			log.debug("Destination NTWK switch set and configured!");
		}
		// For now, let's assume we have two DPIDs as in our config file.
		if (SRC_AGENT_SWITCH_DPID.equals(sw.getId())) {
			SRC_AGENT_SWITCH = new SOSSwitch(sw);
			SRC_AGENT_SWITCH.addClient(SRC_CLIENT);
			SRC_AGENT_SWITCH.setLocalAgent(SRC_AGENT);
			log.debug("Source AGENT switch set and configured!");
		}
		// Not an else-if... we may want two agents on a single switch for whatever reason
		if (DST_AGENT_SWITCH_DPID.equals(sw.getId())) {
			DST_AGENT_SWITCH = new SOSSwitch(sw);
			DST_AGENT_SWITCH.addClient(DST_CLIENT);
			DST_AGENT_SWITCH.setLocalAgent(DST_AGENT);
			log.debug("Destination AGENT switch set and configured!");
		}

		/* 
		 * In the future, we'll do somthing like this...
		for (SOSSwitch sosSw : SOS_SWITCHES) {
			if (sosSw.getSwitch() == sw) {
				// If we find it, then it's already there, so return w/o adding
				return;
			}
		}
		// We must not have found it, so add it
		SOS_SWITCHES.add(new SOSSwitch(sw));
		 */
	}

	@Override
	public void switchRemoved(DatapathId dpid) {
		// For now, let's assume we only have two DPIDs as in our config file.
		IOFSwitch sw = switchService.getSwitch(dpid);
		if (SRC_NTWK_SWITCH_DPID.equals(sw.getId())) {
			SRC_NTWK_SWITCH.removeClient(SRC_CLIENT);
			SRC_NTWK_SWITCH = null;
		} else if (DST_NTWK_SWITCH_DPID.equals(sw.getId())) {
			DST_NTWK_SWITCH.removeClient(DST_CLIENT);
			DST_NTWK_SWITCH = null;
		} else if (SRC_AGENT_SWITCH_DPID.equals(sw.getId())) {
			SRC_AGENT_SWITCH.removeClient(SRC_CLIENT);
			SRC_AGENT_SWITCH = null;
		} else if (DST_AGENT_SWITCH_DPID.equals(sw.getId())) {
			DST_AGENT_SWITCH.removeClient(DST_CLIENT);
			DST_AGENT_SWITCH = null;
		}

		/*
		 *  In the future, we'll do something like this...
		for (SOSSwitch sosSw : SOS_SWITCHES) {
			if (sosSw.getSwitch() == sw) {
				// Do something to remove all Agent and Client associations to this switch instance
				// ...and unfortunately terminate any SOS connections as well...

				// Now remove the switch from our list
				SOS_SWITCHES.remove(sosSw);
			}
		}
		 */
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
}