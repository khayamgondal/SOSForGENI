package net.floodlightcontroller.sos;

import java.util.Date;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSWhitelistEntrySerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSWhitelistEntrySerializer.class)
public class SOSWhitelistEntry implements ISOSWhitelistEntry {
	private IPv4Address serverIp;
	private IPv4Address clientIp;
	private TransportPort serverPort;
	private Date startTime;
	private Date stopTime;
	
	private SOSWhitelistEntry(IPv4Address serverIp, TransportPort serverPort, IPv4Address clientIp, Date startTime, Date stopTime) {
		this.serverIp = serverIp;
		this.serverPort = serverPort;
		this.clientIp = clientIp;
		this.startTime = startTime;
		this.stopTime = stopTime;
	}
	
	public static ISOSWhitelistEntry of(IPv4Address serverIp, TransportPort serverPort, IPv4Address clientIp) {
		return of(serverIp, serverPort, clientIp, NO_RESERVTION, NO_RESERVTION);
	}
	
	public static ISOSWhitelistEntry of(IPv4Address serverIp, TransportPort serverPort, IPv4Address clientIp, Date startTime, Date stopTime) {
		if (serverIp == null || serverIp.equals(IPv4Address.NONE)) {
			throw new IllegalArgumentException("Server IP must be a valid IP. Was " + serverIp == null ? "null" : serverIp.toString());
		}
		if (serverPort == null || serverPort.equals(TransportPort.NONE)) {
			throw new IllegalArgumentException("Server port must be a valid port. Was " + serverPort == null ? "null" : serverPort.toString());
		}
		if (clientIp == null || clientIp.equals(IPv4Address.NONE)) {
			throw new IllegalArgumentException("Client IP must be a valid IP. Was " + clientIp == null ? "null" : clientIp.toString());
		}
		if (startTime == null) {
			throw new IllegalArgumentException("Start time must not be null.");
		}
		if (stopTime == null) {
			throw new IllegalArgumentException("Stop time must not be null.");
		}
		
		return new SOSWhitelistEntry(serverIp, serverPort, clientIp, startTime, stopTime);
	}
	
	@Override
	public IPv4Address getServerIP() {
		return serverIp;
	}
	
	@Override
	public TransportPort getServerPort() {
		return serverPort;
	}
	
	@Override
	public IPv4Address getClientIP() {
		return clientIp;
	}
	
	@Override
	public Date getStartTime() {
		return startTime;
	}

	@Override 
	public Date getStopTime() {
		return stopTime;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((clientIp == null) ? 0 : clientIp.hashCode());
		result = prime * result
				+ ((serverIp == null) ? 0 : serverIp.hashCode());
		result = prime * result
				+ ((serverPort == null) ? 0 : serverPort.hashCode());
		result = prime * result
				+ ((startTime == null) ? 0 : startTime.hashCode());
		result = prime * result
				+ ((stopTime == null) ? 0 : stopTime.hashCode());
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
		SOSWhitelistEntry other = (SOSWhitelistEntry) obj;
		if (clientIp == null) {
			if (other.clientIp != null)
				return false;
		} else if (!clientIp.equals(other.clientIp))
			return false;
		if (serverIp == null) {
			if (other.serverIp != null)
				return false;
		} else if (!serverIp.equals(other.serverIp))
			return false;
		if (serverPort == null) {
			if (other.serverPort != null)
				return false;
		} else if (!serverPort.equals(other.serverPort))
			return false;
		if (startTime == null) {
			if (other.startTime != null)
				return false;
		} else if (!startTime.equals(other.startTime))
			return false;
		if (stopTime == null) {
			if (other.stopTime != null)
				return false;
		} else if (!stopTime.equals(other.stopTime))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SOSRegistered [serverIp=" + serverIp + ", clientIp=" + clientIp
				+ ", serverPort=" + serverPort + "]";
	}
}