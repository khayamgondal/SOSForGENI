package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.UUID;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.TransportPort;

public class SOSConnection {
	private SOSClient SRC_CLIENT;
	private SOSAgent SRC_AGENT;
	private TransportPort SRC_PORT;
	private SOSClient DST_CLIENT;
	private SOSAgent DST_AGENT;
	private TransportPort DST_PORT;
	private TransportPort DST_AGENT_L4PORT;
	private DatapathId SRC_AGENT_SWITCH;
	private DatapathId DST_AGENT_SWITCH;
	private DatapathId SRC_NTWK_SWITCH;
	private DatapathId DST_NTWK_SWITCH;
	private UUID TRANSFER_ID;
	private int NUM_PARALLEL_SOCKETS;
	private int QUEUE_CAPACITY;
	private int BUFFER_SIZE;
	private ArrayList<String> FLOW_NAMES;
	
	public SOSConnection(SOSClient srcC, SOSAgent srcA, TransportPort srcP, DatapathId srcS, 
			SOSClient dstC, SOSAgent dstA, TransportPort dstP, DatapathId dstS, DatapathId srcNtwkS, DatapathId dstNtwkS, int numSockets, int queueCap, int bufSize) {
		SRC_CLIENT = srcC;
		SRC_AGENT = srcA;
		SRC_PORT = srcP;
		SRC_AGENT_SWITCH = srcS;
		DST_CLIENT = dstC;
		DST_AGENT = dstA;
		DST_PORT = dstP;
		DST_AGENT_L4PORT = TransportPort.NONE; // This cannot be known when the first TCP packet is received. It will be learned on the dst-side
		DST_AGENT_SWITCH = dstS;
		SRC_NTWK_SWITCH = srcNtwkS;
		DST_NTWK_SWITCH = dstNtwkS;
		TRANSFER_ID = UUID.randomUUID();
		NUM_PARALLEL_SOCKETS = numSockets;
		QUEUE_CAPACITY = queueCap;
		BUFFER_SIZE = bufSize;
		FLOW_NAMES = new ArrayList<String>();
	}
	
	public TransportPort getDstAgentL4Port() {
		return DST_AGENT_L4PORT;
	}
	public void setDstAgentL4Port(TransportPort l4port) {
		DST_AGENT_L4PORT = l4port;
	}
	
	public DatapathId getSrcAgentSwitch() {
		return SRC_AGENT_SWITCH;
	}
	public DatapathId getDstAgentSwitch() {
		return DST_AGENT_SWITCH;
	}
	public DatapathId getSrcNtwkSwitch() {
		return SRC_NTWK_SWITCH;
	}
	public DatapathId getDstNtwkSwitch() {
		return DST_NTWK_SWITCH;
	}
	
	public SOSAgent getSrcAgent() {
		return SRC_AGENT;
	}
	public SOSAgent getDstAgent() {
		return DST_AGENT;
	}
	
	public SOSClient getSrcClient() {
		return SRC_CLIENT;
	}
	public SOSClient getDstClient() {
		return DST_CLIENT;
	}
	
	public TransportPort getSrcPort() {
		return SRC_PORT;
	}
	public TransportPort getDstPort() {
		return DST_PORT;
	}
	
	public UUID getTransferID() {
		return TRANSFER_ID;
	}
	
	public int getNumParallelSockets() {
		return NUM_PARALLEL_SOCKETS;
	}
	
	public int getQueueCapacity() {
		return QUEUE_CAPACITY;
	}
	
	public int getBufferSize() {
		return BUFFER_SIZE;
	}
	
	public ArrayList<String> getFlowNames() {
		return FLOW_NAMES;
	}
	public void removeFlow(String flowName) {
		FLOW_NAMES.remove(flowName);
	}
	public void removeFlows() {
		FLOW_NAMES.clear();
	}
	public void addFlow(String flowName) {
		if (!FLOW_NAMES.contains(flowName)) {
			FLOW_NAMES.add(flowName);
		}
	}
	public void addFlows(ArrayList<String> flowNames) {
		for (String flow : flowNames) {
			addFlow(flow);
		}
	}
	public void replaceFlowsWith(ArrayList<String> flowNames) {
		removeFlows();
		addFlows(flowNames);
	}
	
	@Override
	public String toString() {
		/*
		SRC_PORT = srcP;
		DST_PORT = dstP;
		FLOW_NAMES = new ArrayList<String>();*/
		String output;
		output = "Transfer ID: " + TRANSFER_ID.toString() + "\r\n" +
					"|| Sockets: " + NUM_PARALLEL_SOCKETS + "\r\n" +
					"Queue Capacity: " + QUEUE_CAPACITY + "\r\n" +
					"Buffer Size: " + BUFFER_SIZE + "\r\n" +
					"Source Agent Switch: " + SRC_AGENT_SWITCH + "\r\n" +
					"Source Network Switch: " + SRC_NTWK_SWITCH + "\r\n" +
					"Destination Agent Switch: " + DST_AGENT_SWITCH + "\r\n" +
					"Destination Network Switch: " + DST_NTWK_SWITCH + "\r\n" +
					"Source Agent: (" + SRC_AGENT.getIPAddr().toString() + ", " + SRC_AGENT.getAttachmentPoint().toString() + ")\r\n" +
					"Destination Agent: (" + DST_AGENT.getIPAddr().toString() + ", " + DST_AGENT.getAttachmentPoint().toString() + ")\r\n" +
					"Source Client: (" + SRC_CLIENT.getIPAddr().toString() + ", " + SRC_CLIENT.getAttachmentPoint().toString() + ")\r\n" +
					"Destination Client: (" + DST_CLIENT.getIPAddr().toString() + ", " + DST_CLIENT.getAttachmentPoint().toString() + ")\r\n" +
					"Source L4 Port: " + SRC_PORT.toString() + "\r\n" +
					"Destination L4 Port: " + DST_PORT.toString() + "\r\n" +
		    		"Destination Agent L4 Port: " + DST_AGENT_L4PORT.toString() + "\r\n";

		return output;
	}
}