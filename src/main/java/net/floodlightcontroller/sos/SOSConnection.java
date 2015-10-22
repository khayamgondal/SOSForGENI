package net.floodlightcontroller.sos;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.projectfloodlight.openflow.types.TransportPort;

public class SOSConnection {
	private SOSRoute clientToAgent;
	private SOSRoute agentToAgent;
	private SOSRoute serverToAgent;
	private TransportPort serverAgentPort;
	private UUID transferId;
	private int numParallelSockets;
	private int queueCapacity;
	private int bufferSize;
	private int flowTimeout;
	private Set<String> flowNames;
	
	public SOSConnection(SOSRoute clientToAgent, SOSRoute interAgent,
			SOSRoute serverToAgent, int numSockets, 
			int queueCapacity, int bufferSize,
			int flowTimeout) {
		if (clientToAgent.getRouteType() != SOSRouteType.CLIENT_2_AGENT) {
			throw new IllegalArgumentException("SOSRoute clientToAgent must be of type client-to-agent");
		}
		this.clientToAgent = clientToAgent;
		if (interAgent.getRouteType() != SOSRouteType.AGENT_2_AGENT) {
			throw new IllegalArgumentException("SOSRoute interAgent must be of type agent-to-agent");
		}
		this.agentToAgent = interAgent;
		if (serverToAgent.getRouteType() != SOSRouteType.SERVER_2_AGENT) {
			throw new IllegalArgumentException("SOSRoute serverToAgent must be of type server-to-agent");
		}
		this.serverToAgent = serverToAgent;
		this.serverAgentPort = TransportPort.NONE; /* This cannot be known when the first TCP packet is received. It will be learned on the server-side */
		this.transferId = UUID.randomUUID();
		((SOSAgent) this.clientToAgent.getDstDevice()).addTransferId(this.transferId); /* agents can be shared; update them w/UUID */
		((SOSAgent) this.serverToAgent.getDstDevice()).addTransferId(this.transferId);
		this.numParallelSockets = numSockets;
		this.queueCapacity = queueCapacity;
		this.bufferSize = bufferSize;
		this.flowTimeout = flowTimeout;
		this.flowNames = new HashSet<String>();
	}
	
	/**
	 * First hop is the OpenFlow switch nearest
	 * the client; last hop is the OpenFlow switch
	 * nearest the client-side agent.
	 * @return
	 */
	public SOSRoute getClientSideRoute() {
		return this.clientToAgent;
	}
	
	/**
	 * First hop is the OpenFlow switch nearest
	 * the client-side agent; last hop is the 
	 * OpenFlow switch nearest the server-side agent.
	 * @return
	 */
	public SOSRoute getInterAgentRoute() {
		return this.agentToAgent;
	}
	
	/**
	 * First hop is the OpenFlow switch nearest
	 * the server; last hop is the OpenFlow switch
	 * nearest the server-side agent.
	 * @return
	 */
	public SOSRoute getServerSideRoute() {
		return this.serverToAgent;
	}
	
	public TransportPort getServerSideAgentTcpPort() {
		return serverAgentPort;
	}
	
	public void setServerSideAgentTcpPort(TransportPort port) {
		serverAgentPort = port;
	}
	
	public SOSAgent getClientSideAgent() {
		return (SOSAgent) this.clientToAgent.getDstDevice();
	}
	
	public SOSAgent getServerSideAgent() {
		return (SOSAgent) this.serverToAgent.getDstDevice();
	}
	
	public SOSClient getClient() {
		return (SOSClient) this.clientToAgent.getSrcDevice();
	}
	public SOSServer getServer() {
		return (SOSServer) this.serverToAgent.getSrcDevice();
	}
	
	public UUID getTransferID() {
		return transferId;
	}
	
	public int getNumParallelSockets() {
		return numParallelSockets;
	}
	
	public int getQueueCapacity() {
		return queueCapacity;
	}
	
	public int getBufferSize() {
		return bufferSize;
	}
	
	public int getFlowTimeout() {
		return flowTimeout;
	}
	
	public Set<String> getFlowNames() {
		return flowNames;
	}
	
	public void removeFlow(String flowName) {
		flowNames.remove(flowName);
	}
	
	public void removeFlows() {
		flowNames.clear();
	}
	
	public void addFlow(String flowName) {
		if (!flowNames.contains(flowName)) {
			flowNames.add(flowName);
		}
	}
	
	public void addFlows(Set<String> flowNames) {
		for (String flow : flowNames) {
			addFlow(flow);
		}
	}
	
	public String getName() {
		return transferId.toString();
	}

	@Override
	public String toString() {
		return "SOSConnection [clientToAgent=" + clientToAgent
				+ ", agentToAgent=" + agentToAgent + ", serverToAgent="
				+ serverToAgent + ", serverAgentPort="
				+ serverAgentPort + ", transferId=" + transferId
				+ ", numParallelSockets=" + numParallelSockets
				+ ", queueCapacity=" + queueCapacity + ", bufferSize="
				+ bufferSize + ", flowTimeout=" + flowTimeout + ", flowNames=" + flowNames + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((agentToAgent == null) ? 0 : agentToAgent.hashCode());
		result = prime * result + bufferSize;
		result = prime * result
				+ ((clientToAgent == null) ? 0 : clientToAgent.hashCode());
		result = prime * result
				+ ((flowNames == null) ? 0 : flowNames.hashCode());
		result = prime * result + numParallelSockets;
		result = prime * result + queueCapacity;
		result = prime * result + flowTimeout;
		result = prime * result
				+ ((serverAgentPort == null) ? 0 : serverAgentPort.hashCode());
		result = prime * result
				+ ((serverToAgent == null) ? 0 : serverToAgent.hashCode());
		result = prime * result
				+ ((transferId == null) ? 0 : transferId.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SOSConnection other = (SOSConnection) obj;
		if (agentToAgent == null) {
			if (other.agentToAgent != null)
				return false;
		} else if (!agentToAgent.equals(other.agentToAgent))
			return false;
		if (bufferSize != other.bufferSize)
			return false;
		if (clientToAgent == null) {
			if (other.clientToAgent != null)
				return false;
		} else if (!clientToAgent.equals(other.clientToAgent))
			return false;
		if (flowNames == null) {
			if (other.flowNames != null)
				return false;
		} else if (!flowNames.equals(other.flowNames))
			return false;
		if (numParallelSockets != other.numParallelSockets)
			return false;
		if (queueCapacity != other.queueCapacity)
			return false;
		if (flowTimeout != other.flowTimeout)
			return false;
		if (serverAgentPort == null) {
			if (other.serverAgentPort != null)
				return false;
		} else if (!serverAgentPort.equals(other.serverAgentPort))
			return false;
		if (serverToAgent == null) {
			if (other.serverToAgent != null)
				return false;
		} else if (!serverToAgent.equals(other.serverToAgent))
			return false;
		if (transferId == null) {
			if (other.transferId != null)
				return false;
		} else if (!transferId.equals(other.transferId))
			return false;
		return true;
	}
}