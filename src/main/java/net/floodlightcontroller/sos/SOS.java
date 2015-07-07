package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/*TODO: We might eventually use these to automatically remove flows
 * import java.util.concurrent.ScheduledThreadPoolExecutor;
 * import java.util.concurrent.TimeUnit;
 */

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
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
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
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.forwarding.Forwarding;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;


/**
 * Steroid OpenFlow Service Module
 * @author Ryan Izard, rizard@g.clemson.edu
 * 
 */
public class SOS implements IOFMessageListener, IOFSwitchListener, IFloodlightModule  {
	protected static Logger log;
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected ITopologyService topologyService;
	protected IRoutingService routingService;
	protected IDeviceService deviceService;
	protected IStaticFlowEntryPusherService sfp;

	private static MacAddress CONTROLLER_MAC;
	private static IPv4Address CONTROLLER_IP;
	private static TransportPort AGENT_UDP_MSG_IN_PORT; // 9998
	private static TransportPort AGENT_TCP_IN_PORT; // 9877

	private static SOSAgent SRC_AGENT;
	private static SOSAgent DST_AGENT;

	private static SOSClient SRC_CLIENT;
	private static SOSClient DST_CLIENT;

	private static SOSSwitch SRC_NTWK_SWITCH;
	private static SOSSwitch DST_NTWK_SWITCH;
	private static SOSSwitch SRC_AGENT_SWITCH;
	private static SOSSwitch DST_AGENT_SWITCH;
	/*TODO: maintain a list of SOS switches so we can algorithmically determine the source
	 * and destination agent switches.
	 * private static ArrayList<SOSSwitch> SOS_SWITCHES;
	 */

	private static SOSActiveConnections SOS_CONNECTIONS;

	private static int BUFFER_SIZE;
	private static int QUEUE_CAPACITY;
	private static int PARALLEL_SOCKETS;
	private static short FLOW_TIMEOUT; // TODO: have a timeout/gc thread to clean up old flows (since static flows do not support idle/hard timeouts)

	/* These are things that will be automated with a discovery service */
	private static MacAddress SRC_CLIENT_MAC;
	private static IPv4Address SRC_CLIENT_IP;
	private static OFPort SRC_CLIENT_PORT;
	private static MacAddress DST_CLIENT_MAC;
	private static IPv4Address DST_CLIENT_IP;
	private static OFPort DST_CLIENT_PORT;

	private static MacAddress SRC_AGENT_MAC;
	private static IPv4Address SRC_AGENT_IP;
	private static OFPort SRC_AGENT_PORT;
	private static OFPort SRC_AGENT_OVS_PORT;
	private static MacAddress DST_AGENT_MAC;
	private static IPv4Address DST_AGENT_IP;
	private static OFPort DST_AGENT_PORT;
	private static OFPort DST_AGENT_OVS_PORT;

	private static DatapathId SRC_AGENT_SWITCH_DPID;
	private static DatapathId DST_AGENT_SWITCH_DPID;
	private static DatapathId SRC_NTWK_SWITCH_DPID;
	private static DatapathId DST_NTWK_SWITCH_DPID;

	/* TODO: Use these if we need to to insert flows to the delay machine's ports (or simply to a real network) */
	private static OFPort SRC_NTWK_PORT;
	private static OFPort DST_NTWK_PORT;

	public static final MacAddress BROADCAST_MAC = MacAddress.BROADCAST;
	public static final IPv4Address BROADCAST_IP = IPv4Address.NO_MASK; /* all 1's */
	public static final IPv4Address UNASSIGNED_IP = IPv4Address.FULL_MASK; /* all 0's */

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
		log = LoggerFactory.getLogger(SOS.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);

		// Read our config options
		Map<String, String> configOptions = context.getConfigParams(this);
		try {
			CONTROLLER_MAC = MacAddress.of(configOptions.get("controller-mac"));
			CONTROLLER_IP = IPv4Address.of(configOptions.get("controller-ip"));

			BUFFER_SIZE = Integer.parseInt(configOptions.get("buffer-size"));
			QUEUE_CAPACITY = Integer.parseInt(configOptions.get("queue-capacity"));
			PARALLEL_SOCKETS = Integer.parseInt(configOptions.get("parallel-tcp-sockets"));
			FLOW_TIMEOUT = Short.parseShort(configOptions.get("flow-timeout"));

			AGENT_UDP_MSG_IN_PORT = TransportPort.of(Integer.parseInt(configOptions.get("agent-msg-port")));
			AGENT_TCP_IN_PORT = TransportPort.of(Integer.parseInt(configOptions.get("agent-tcp-port")));

			/* Get rid of these after we implement a discovery service
			SRC_CLIENT_MAC = Ethernet.toMACAddress(configOptions.get("src-client-mac"));
			SRC_CLIENT_IP = IPv4.toIPv4Address(configOptions.get("src-client-ip"));
			SRC_CLIENT_PORT = Short.parseShort(configOptions.get("src-client-sw-port"));
			DST_CLIENT_MAC = Ethernet.toMACAddress(configOptions.get("dst-client-mac"));
			DST_CLIENT_IP = IPv4.toIPv4Address(configOptions.get("dst-client-ip")); */
			DST_CLIENT_PORT = OFPort.of(Integer.parseInt(configOptions.get("dst-client-sw-port")));


			SRC_AGENT_MAC = MacAddress.of(configOptions.get("src-agent-mac"));
			SRC_AGENT_IP = IPv4Address.of(configOptions.get("src-agent-ip"));
			SRC_AGENT_PORT = OFPort.of(Integer.parseInt(configOptions.get("src-agent-sw-port")));
			SRC_AGENT_OVS_PORT = OFPort.of(Integer.parseInt(configOptions.get("src-agent-ovs-port")));
			DST_AGENT_MAC = MacAddress.of(configOptions.get("dst-agent-mac"));
			DST_AGENT_IP = IPv4Address.of(configOptions.get("dst-agent-ip"));
			DST_AGENT_PORT = OFPort.of(Integer.parseInt(configOptions.get("dst-agent-sw-port")));
			DST_AGENT_OVS_PORT = OFPort.of(Integer.parseInt(configOptions.get("src-agent-ovs-port")));

			SRC_AGENT_SWITCH_DPID = DatapathId.of(configOptions.get("src-agent-switch-dpid"));
			DST_AGENT_SWITCH_DPID = DatapathId.of(configOptions.get("dst-agent-switch-dpid"));
			SRC_NTWK_SWITCH_DPID = DatapathId.of(configOptions.get("src-ntwk-switch-dpid"));
			DST_NTWK_SWITCH_DPID = DatapathId.of(configOptions.get("dst-ntwk-switch-dpid"));

			SRC_NTWK_PORT = OFPort.of(Integer.parseInt(configOptions.get("src-ntwk-sw-port")));
			DST_NTWK_PORT = OFPort.of(Integer.parseInt(configOptions.get("dst-ntwk-sw-port")));

		} catch(IllegalArgumentException ex) {
			log.error("Incorrect SOS configuration options", ex);
			throw ex;
		} catch(NullPointerException ex) {
			log.error("Incorrect SOS configuration options", ex);
			throw ex;
		}

		SOS_CONNECTIONS = new SOSActiveConnections();
		// Do this later when we use discovery SOS_SWITCHES = new ArrayList<SOSSwitch>();

		SRC_AGENT = new SOSAgent(SRC_AGENT_IP, SRC_AGENT_MAC, 0, SRC_AGENT_PORT);
		DST_AGENT = new SOSAgent(DST_AGENT_IP, DST_AGENT_MAC, 1, DST_AGENT_PORT);

		//SRC_CLIENT = new SOSClient(SRC_CLIENT_IP, SRC_CLIENT_MAC, SRC_AGENT, SRC_CLIENT_PORT);
		//DST_CLIENT = new SOSClient(DST_CLIENT_IP, DST_CLIENT_MAC, DST_AGENT, DST_CLIENT_PORT);

		SRC_NTWK_SWITCH = new SOSSwitch();
		DST_NTWK_SWITCH = new SOSSwitch();

		SRC_AGENT_SWITCH = new SOSSwitch();
		DST_AGENT_SWITCH = new SOSSwitch();
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
		// Allow the CONTEXT_DST_DEVICE field to be populated by the DeviceManager. This makes our job easier :)
		if (type == OFType.PACKET_IN && name.equalsIgnoreCase(DeviceManagerImpl.class.getSimpleName())) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		if (type == OFType.PACKET_IN && name.equals("forwarding")) {
			log.debug("SOS is telling Forwarding to run later.");
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Send an OF packet with the UDP packet encapsulated inside. This packet is destined for
	 * the agent. 
	 * 
	 * @param conn, The associated SOSConnection for the UDP info packets.
	 * @param isSourceAgent, Send to source agent (true); send to destination agent (false).
	 */
	public void sendInfoToAgent(FloodlightContext cntx, SOSConnection conn, boolean isSourceAgent) {
		/* OF packet to send to the switches. The switches will be the switch
		 * of the source agent and the switch of the destination agent
		 */
		OFFactory factory;
		if (isSourceAgent) {
			factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();
		} else {
			factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();
		}

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* L2 of packet */
		Ethernet l2 = new Ethernet();
		l2.setSourceMACAddress(CONTROLLER_MAC);
		l2.setDestinationMACAddress(isSourceAgent ? conn.getSrcAgent().getMACAddr() : conn.getDstAgent().getMACAddr());
		l2.setEtherType(EthType.IPv4);

		/* L3 of packet */
		IPv4 l3 = new IPv4();
		l3.setSourceAddress(isSourceAgent ? conn.getDstAgent().getIPAddr() : conn.getDstClient().getIPAddr());
		l3.setDestinationAddress(isSourceAgent ? conn.getSrcAgent().getIPAddr() : conn.getDstAgent().getIPAddr());
		l3.setProtocol(IpProtocol.UDP);
		l3.setTtl((byte) 64);

		/* L4 of packet */
		UDP l4 = new UDP();
		l4.setSourcePort(conn.getDstPort());
		l4.setDestinationPort(AGENT_UDP_MSG_IN_PORT);


		/* Convert the string into IPacket. Data extends BasePacket, which is an abstract class
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
		if (isSourceAgent) {
			/*payload = "CLIENT " + str(transfer_id) + 
					" " + ip_to_str(packet.next.srcip)  + 
					" " + str(packet.next.next.srcport) + 
					" " +  ip_to_str(inst.Agent[FA]['ip']) + 
					" "  + str(NUM_CONNECTIONS) + 
					" "  + str(BUFSIZE) + 
					" " +str(MAX_QUEUE_SIZE) */
			log.debug(conn.getTransferID().toString());
			agentInfo = "CLIENT " + conn.getTransferID().toString() + 
					" " + conn.getSrcClient().getIPAddr().toString() +
					" " + conn.getSrcPort().toString() +
					" " + conn.getDstAgent().getIPAddr().toString() +
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
					" " + conn.getDstClient().getIPAddr().toString() +
					" " + conn.getDstPort().toString() +
					/* I suppose the destination agent will learn the source agent IP
					 * after it receives the first TCP packet (hopefully this is true)
					 */
					" " + Integer.toString(conn.getNumParallelSockets()) +
					" " + Integer.toString(conn.getBufferSize()) +
					" " + Integer.toString(conn.getQueueCapacity());
		}

		Data payloadData = new Data();

		/* Construct the packet layer-by-layer */
		l2.setPayload(l3.setPayload(l4.setPayload(payloadData.setData(agentInfo.getBytes()))));

		/* Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		if (isSourceAgent) {
			actions.add(factory.actions().output(OFPort.of(1), 0xffFFffFF));
		} else {
			actions.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));
		}
		ofPacket.setActions(actions);

		/* Put the UDP packet in the OF packet (encapsulate it as an OF packet) */
		byte[] udpPacket = l2.serialize();
		ofPacket.setData(udpPacket);

		/* Send the OF packet to the agent switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * UDP packet out the port specified.
		 */
		if (isSourceAgent) {
			conn.getSrcAgentSwitch().getSwitch().write(ofPacket.build());
		} else {
			conn.getDstAgentSwitch().getSwitch().write(ofPacket.build());
		}
	}
	/**
	 * Send an OF packet with the TCP "spark" packet (the packet that "sparked" the SOS session)
	 * encapsulated inside. This packet is destined for the source agent. 
	 * 
	 * @param l2, the Ethernet packet received by the SOS module.
	 * @param conn, The associated SOSConnection for the UDP info packets.
	 */
	public void sendSrcSparkPacket(FloodlightContext cntx, Ethernet l2, SOSConnection conn) {
		/* OF packet to send to the switches. The switches will be the switch
		 * of the source agent and the switch of the destination agent
		 */
		OFFactory factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* L2 of packet
		 * Change the dst MAC to the agent
		 */
		l2.setDestinationMACAddress(conn.getSrcAgent().getMACAddr());

		/* L3 of packet 
		 * Change the dst IP to the agent
		 */
		IPv4 l3 = (IPv4) l2.getPayload();
		l3.setDestinationAddress(conn.getSrcAgent().getIPAddr());

		/* L4 of packet 
		 * Change destination TCP port to the one the agent is listening to
		 */
		TCP l4 = (TCP) l3.getPayload();
		l4.setDestinationPort(AGENT_TCP_IN_PORT);

		/* Reconstruct the packet layer-by-layer 
		 * Only the L2 MAC and L3 IP were changed.
		 * L4 info is preserved in l3 payload.
		 */
		l3.setPayload(l4);
		l2.setPayload(l3);

		/* Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		/* Output to the source agent */
		actions.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));
		ofPacket.setActions(actions);

		/* Put the TCP spark packet in the OF packet (encapsulate it as an OF packet) */
		ofPacket.setData(l2.serialize());

		/* Send the OF packet to the agent switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * UDP packet out the port specified.
		 */
		conn.getSrcAgentSwitch().getSwitch().write(ofPacket.build());
	}
	/**
	 * Send an OF packet with the TCP "spark" packet (the packet that "sparked" the SOS session)
	 * encapsulated inside. This packet is destined for the source agent. 
	 * 
	 * @param l2, the Ethernet packet received by the SOS module.
	 * @param conn, The associated SOSConnection for the UDP info packets.
	 */
	public void sendDstSparkPacket(FloodlightContext cntx, Ethernet l2, SOSConnection conn) {
		/* OF packet to send to the switches. The switches will be the switch
		 * of the source agent and the switch of the destination agent
		 */
		OFFactory factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();

		OFPacketOut.Builder ofPacket = factory.buildPacketOut();
		ofPacket.setBufferId(OFBufferId.NO_BUFFER);

		/* L2 of packet
		 * Change the dst MAC to the agent
		 */
		l2.setSourceMACAddress(conn.getSrcClient().getMACAddr());

		/* L3 of packet 
		 * Change the dst IP to the agent
		 */
		IPv4 l3 = (IPv4) l2.getPayload();
		l3.setSourceAddress(conn.getSrcClient().getIPAddr());

		/* L4 of packet 
		 * Change destination TCP port to the one the agent is listening to
		 */
		TCP l4 = (TCP) l3.getPayload();
		l4.setSourcePort(conn.getDstAgentL4Port());

		/* Reconstruct the packet layer-by-layer 
		 * Only the L2 MAC and L3 IP were changed.
		 * L4 info is preserved in l3 payload.
		 */
		l3.setPayload(l4);
		l2.setPayload(l3);

		/* Tell the switch what to do with the packet. This is specified as an OFAction.
		 * i.e. Which port should it go out?
		 */
		ofPacket.setInPort(OFPort.ANY);
		List<OFAction> actions = new ArrayList<OFAction>();
		/* Output to the source agent */
		actions.add(factory.actions().output(OFPort.LOCAL, 0xffFFffFF));
		ofPacket.setActions(actions);

		/* Put the TCP spark packet in the OF packet (encapsulate it as an OF packet) */
		ofPacket.setData(l2.serialize());

		/* Send the OF packet to the agent switch.
		 * The switch will look at the OpenFlow action and send the encapsulated
		 * UDP packet out the port specified.
		 */
		conn.getDstAgentSwitch().getSwitch().write(ofPacket.build());
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if (!sw.getId().equals(SRC_AGENT_SWITCH_DPID) && !sw.getId().equals(DST_AGENT_SWITCH_DPID)
				&& !sw.getId().equals(SRC_NTWK_SWITCH_DPID) && !sw.getId().equals(DST_NTWK_SWITCH_DPID)) {
			return Command.CONTINUE;
		}

		OFPacketIn pi = (OFPacketIn) msg;

		Ethernet l2 = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (l2.getEtherType() == EthType.IPv4) {
			log.debug("Got IPv4 Packet");
			IPv4 l3 = (IPv4) l2.getPayload();
			log.debug("{}", l3.getProtocol());

			if (l3.getProtocol().equals(IpProtocol.TCP)) {
				log.debug("Got TCP Packet on port " + (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort().toString() : pi.getMatch().get(MatchField.IN_PORT).toString()) + " of switch " + sw.getId());
				TCP l4 = (TCP) l3.getPayload();
				/* If this source IP and source port (or destination IP and destination port)
				 * have already been assigned a connection then we really shouldn't get to 
				 * this point. Flows matching the source IP and source port should have already \
				 * been inserted switching those packets to the source agent. 
				 */

				/* Lookup the source IP address to see if it belongs to a client with a connection */
				log.debug("(" + l4.getSourcePort().toString() + ", " + l4.getDestinationPort().toString() + ")");

				SOSConnectionPacketMembership packetStatus = SOS_CONNECTIONS.isPacketMemberOfActiveConnection(
						l3.getSourceAddress(), l3.getDestinationAddress(),
						l4.getSourcePort(), l4.getDestinationPort()); 

				if (packetStatus == SOSConnectionPacketMembership.NOT_ASSOCIATED_WITH_ACTIVE_SOS_CONNECTION){
					/* Process new TCP SOS session */

					/* Create new Source Client */
					SOSClient sourceClient = new SOSClient(l3.getSourceAddress(), l2.getSourceMACAddress(), (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)));
					sourceClient.setAgent(SRC_AGENT); //TODO figure out a way to detect the closest agent

					/* Create a new Source Physical Switch */
					SOSSwitch sourceSwitch = new SOSSwitch(sw);

					/* Destination switch will not be known at this point.
					 * Fortunately, if we let the device listener go before
					 * our module, the destination device will be set to
					 * the context using private/protected DM methods.
					 * 
					 * TODO: We should send e.g. an ARP request to the
					 * destination IP if the device was not found.
					 *
					IDevice destinationDevice = (IDevice) cntx.getStorage().get(DeviceManagerImpl.CONTEXT_DST_DEVICE);
					long destinationSwitch = destinationDevice.


					if (destinationDevice == null) {
						log.debug("The DeviceManager did not know the destination device. We should handle this...");
					} else {



					}*/

					/* Create new Destination Client */
					SOSClient destinationClient = new SOSClient(l3.getDestinationAddress(), l2.getDestinationMACAddress(), DST_CLIENT_PORT); //TODO get dest port from device mgr
					destinationClient.setAgent(DST_AGENT); //TODO figure out a way to detect the closest agent

					/* Agents should already be created and known */

					/* Establish connection */
					//TODO automatically select source/destination agent/agent-switch and dst-ntwk-switch
					SOSConnection newSOSconnection = SOS_CONNECTIONS.addConnection(sourceClient, SRC_AGENT, l4.getSourcePort(), sourceSwitch, SRC_AGENT_SWITCH,
							destinationClient, DST_AGENT, l4.getDestinationPort(), DST_NTWK_SWITCH, DST_AGENT_SWITCH, PARALLEL_SOCKETS, QUEUE_CAPACITY, BUFFER_SIZE);
					log.debug("Starting new SOS session: \r\n" + newSOSconnection.toString());

					/* Push flows and add flow names to connection (for removal upon termination) */
					log.debug("Pushing source-side and inter-agent SOS flows");
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

					/* Send the initial TCP packet that triggered this module to the home agent */
					log.debug("Sending source-side spark packet to source agent");
					sendSrcSparkPacket(cntx, l2, newSOSconnection);

					/* Send UDP messages to the home and foreign agents */
					log.debug("Sending UDP information packets to source and destination agents");
					sendInfoToAgent(cntx, newSOSconnection, true); // home
					sendInfoToAgent(cntx, newSOSconnection, false); // foreign

				} else if (packetStatus == SOSConnectionPacketMembership.ASSOCIATED_DST_AGENT_TO_DST_CLIENT) {					
					SOSConnection conn = SOS_CONNECTIONS.getConnectionFromIP(l3.getDestinationAddress(), l4.getDestinationPort());

					if (conn == null) {
						log.error("Should have found an SOSConnection in need of a dst-agent L4 port!");
					} else {
						conn.setDstAgentL4Port(l4.getSourcePort());
						log.debug("Finalizing SOS session: \r\n" + conn.toString());

						log.debug("Pushing destination-side SOS flows");
						pushSOSFlow_11(conn);
						pushSOSFlow_12(conn);
						pushSOSFlow_13(conn);
						pushSOSFlow_14(conn);

						log.debug("Sending destination-side spark packet to destination client");
						sendDstSparkPacket(cntx, l2, conn);
					}
				} else {
					log.error("Received a TCP packet that belongs to an ongoing SOS session. Check accuracy of flows!");
				}

				/* We don't want other modules messing with our SOS TCP session (namely Forwarding) */
				return Command.STOP;

			} // END IF TCP packet
		} // END IF IPv4 packet
		return Command.CONTINUE;
	} // END of receive(pkt)

	public void pushSOSFlow_1(SOSConnection conn) {
		OFFactory factory = conn.getSrcNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-1-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcNtwkSwitch().getSwitch().getId() + flowName);
	}
	public void pushSOSFlow_2(SOSConnection conn) {
		OFFactory factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();
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
			actionList.add(factory.actions().setTpDst(AGENT_TCP_IN_PORT));
		} else {
			actionList.add(factory.actions().setField(factory.oxms().ethDst(conn.getSrcAgent().getMACAddr())));
			actionList.add(factory.actions().setField(factory.oxms().ipv4Dst(conn.getSrcAgent().getIPAddr())));
			actionList.add(factory.actions().setField(factory.oxms().tcpDst(AGENT_TCP_IN_PORT)));
		}

		actionList.add(factory.actions().output(OFPort.of(1), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-2-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcAgentSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_3(SOSConnection conn) {
		OFFactory factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.of(1));
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-3-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcAgentSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_4(SOSConnection conn) {
		OFFactory factory = conn.getSrcNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-4-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_5(SOSConnection conn) {
		OFFactory factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, OFPort.of(1));
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-5-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcAgentSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_6(SOSConnection conn) {
		OFFactory factory = conn.getSrcNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-6-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_6a(SOSConnection conn) {
		OFFactory factory = conn.getSrcNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-6a-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_6b(SOSConnection conn) {
		OFFactory factory = conn.getDstNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-6b-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_7(SOSConnection conn) {
		OFFactory factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-7-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstAgentSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_8(SOSConnection conn) {
		OFFactory factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-8-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstAgentSwitch().getSwitch().getId() + flowName);
	} 

	public void pushSOSFlow_9(SOSConnection conn) {
		OFFactory factory = conn.getDstNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-d9-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_9a(SOSConnection conn) {
		OFFactory factory = conn.getDstNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-9a-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_9b(SOSConnection conn) {
		OFFactory factory = conn.getSrcNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-9b-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcNtwkSwitch().getSwitch().getId() + flowName);
	}


	public void pushSOSFlow_10(SOSConnection conn) {
		OFFactory factory = conn.getSrcAgentSwitch().getSwitch().getOFFactory();
		OFFlowAdd.Builder flow = factory.buildFlowAdd();
		Match.Builder match = factory.buildMatch();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();

		match.setExact(MatchField.IN_PORT, SRC_AGENT_OVS_PORT);
		match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		match.setExact(MatchField.IPV4_SRC, conn.getDstAgent().getIPAddr());
		match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
		// Don't care about the TCP port number

		actionList.add(factory.actions().output(OFPort.of(1), 0xffFFffFF));

		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setActions(actionList);
		flow.setMatch(match.build());
		flow.setPriority(32767);
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-10-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getSrcAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getSrcAgentSwitch().getSwitch().getId() + flowName);
	} 

	public void pushSOSFlow_11(SOSConnection conn) {
		OFFactory factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-11-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstAgentSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_12(SOSConnection conn) {
		OFFactory factory = conn.getDstNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-12-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_13(SOSConnection conn) {
		OFFactory factory = conn.getDstNtwkSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-13-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstNtwkSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstNtwkSwitch().getSwitch().getId() + flowName);
	}

	public void pushSOSFlow_14(SOSConnection conn) {
		OFFactory factory = conn.getDstAgentSwitch().getSwitch().getOFFactory();
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
		flow.setIdleTimeout(FLOW_TIMEOUT);

		String flowName = "sos-14-" + conn.getSrcClient().getIPAddr().toString() + 
				"-" + conn.getSrcPort().toString() + 
				"-to-" + conn.getDstClient().getIPAddr().toString() +
				"-" + conn.getDstPort().toString();
		sfp.addFlow(flowName, flow.build(), conn.getDstAgentSwitch().getSwitch().getId());
		conn.addFlow(flowName);
		log.info("added flow on SW " + conn.getDstAgentSwitch().getSwitch().getId() + flowName);
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