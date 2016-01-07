package net.floodlightcontroller.sos;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import net.floodlightcontroller.sos.web.SOSConnectionSerializer;

import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSConnectionSerializer.class)
public interface ISOSConnection {
	
	public ISOSRoute getClientSideRoute();
	
	public ISOSRoute getServerSideRoute();
	
	public ISOSRoute getInterAgentRoute();
	
	public TransportPort getServerSideAgentTcpPort();
	
	public ISOSAgent getClientSideAgent();
	
	public ISOSAgent getServerSideAgent();
	
	public ISOSClient getClient();
	
	public ISOSServer getServer();
	
	public UUID getTransferID();
	
	public int getNumParallelSockets();
	
	public int getQueueCapacity();
	
	public int getBufferSize();
	
	public int getFlowTimeout();
	
	public Date getInitTime();

	public Date getStartTime();

	public Date getStopTime();

	public ISOSTerminationStats getTerminationStats();
	
	public List<ISOSTransferStats> getServerSideTransferStats();
	
	public List<ISOSTransferStats> getClientSideTransferStats();
}