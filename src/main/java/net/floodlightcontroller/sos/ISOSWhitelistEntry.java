package net.floodlightcontroller.sos;

import net.floodlightcontroller.sos.web.SOSWhitelistEntrySerializer;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSWhitelistEntrySerializer.class)
public interface ISOSWhitelistEntry {
	
	/**
	 * Retrieve the IP address of the server
	 * (that will receive the TCP SYN).
	 * @return
	 */
	public IPv4Address getServerIP();
	
	/**
	 * Retrieve the TCP port of the server.
	 * @return
	 */
	public TransportPort getServerPort();
	
	/**
	 * Retrieve the IP address of the client
	 * (initiating the TCP connection).
	 * @return
	 */
	public IPv4Address getClientIP();
}