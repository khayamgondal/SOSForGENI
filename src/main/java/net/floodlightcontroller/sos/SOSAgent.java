package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

public class SOSAgent extends SOSDevice {
	private TransportPort data_port;
	private TransportPort control_port;
	
	public SOSAgent() {
		super(SOSDeviceType.AGENT);
		data_port = TransportPort.NONE;
		control_port = TransportPort.NONE;
	}
	public SOSAgent(IPv4Address ip, TransportPort data, TransportPort control) {
		super(SOSDeviceType.AGENT, ip);
		data_port = data;
		control_port = control;
	}
	
	public TransportPort getDataPort() {
		return data_port;
	}
	
	public TransportPort getControlPort() {
		return control_port;
	}
	
	@Override
	public String toString() {
		return "SOSAgent [ " + super.toString() + " data_port=" + data_port + ", control_port="
				+ control_port + "]";
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result
				+ ((control_port == null) ? 0 : control_port.hashCode());
		result = prime * result
				+ ((data_port == null) ? 0 : data_port.hashCode());
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
		SOSAgent other = (SOSAgent) obj;
		if (control_port == null) {
			if (other.control_port != null)
				return false;
		} else if (!control_port.equals(other.control_port))
			return false;
		if (data_port == null) {
			if (other.data_port != null)
				return false;
		} else if (!data_port.equals(other.data_port))
			return false;
		return true;
	}
}