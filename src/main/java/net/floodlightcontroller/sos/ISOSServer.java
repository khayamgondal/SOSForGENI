package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSServerSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSServerSerializer.class)
public interface ISOSServer extends ISOSDevice {

	public TransportPort getTcpPort();
}