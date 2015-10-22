package net.floodlightcontroller.sos;


import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSServerSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSServerSerializer.class)
public class SOSServer extends SOSDevice implements ISOSServer {
	private TransportPort sock;
	
	public SOSServer(IPv4Address ip, TransportPort p) {
		super(SOSDeviceType.SERVER, ip);
		this.sock = p;
	}
	
	public SOSServer(IPv4Address ip, TransportPort p, MacAddress mac) {
		super(SOSDeviceType.SERVER, ip, mac);
		this.sock = p;
	}
	
	public TransportPort getTcpPort() {
		return this.sock;
	}
	
	@Override
	public String toString() {
		return "SOSServer [ " + super.toString()  + " sock=" + sock.toString() + "]";
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((sock == null) ? 0 : sock.hashCode());
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		SOSServer other = (SOSServer) obj;
		if (sock == null) {
			if (other.sock != null)
				return false;
		} else if (!sock.equals(other.sock))
			return false;
		return true;
	}
}