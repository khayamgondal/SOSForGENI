package net.floodlightcontroller.sos;

import java.util.Date;

import net.floodlightcontroller.sos.web.SOSWhitelistEntrySerializer;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSWhitelistEntrySerializer.class)
public interface ISOSWhitelistEntry {
	public static final Date NO_RESERVTION = new Date(0);
	
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
	
	/**
	 * Retrieve the starting time for which
	 * this whitelist entry becomes valid.
	 * @return
	 */
	public Date getStartTime();
	
	/**
	 * Retrieve the expiration time for
	 * which this whitelist entry is no 
	 * longer valid.
	 * @return
	 */
	public Date getStopTime();
}