package net.floodlightcontroller.sos;

import net.floodlightcontroller.sos.web.SOSClientSerializer;

import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSClientSerializer.class)
public interface ISOSClient extends ISOSDevice {
	
	public TransportPort getTcpPort();
}
