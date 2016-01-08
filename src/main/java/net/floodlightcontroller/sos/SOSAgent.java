package net.floodlightcontroller.sos;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSAgentSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSAgentSerializer.class)
public class SOSAgent extends SOSDevice implements ISOSAgent {
	private TransportPort data_port;
	private TransportPort control_port;
	private TransportPort feedback_port;
	private TransportPort stats_port;

	private Set<UUID> active_transfers;
	
	public SOSAgent() {
		super(SOSDeviceType.AGENT);
		data_port = TransportPort.NONE;
		control_port = TransportPort.NONE;
		feedback_port = TransportPort.NONE;
		stats_port = TransportPort.NONE;
		active_transfers = new HashSet<UUID>();
	}
	public SOSAgent(IPv4Address ip, TransportPort data, TransportPort control, TransportPort feedback, TransportPort stats) {
		super(SOSDeviceType.AGENT, ip);
		data_port = data;
		control_port = control;
		feedback_port = feedback;
		stats_port = stats;
		active_transfers = new HashSet<UUID>();
	}
	
	@Override
	public TransportPort getDataPort() {
		return data_port;
	}
	
	@Override
	public TransportPort getControlPort() {
		return control_port;
	}
	
	@Override
	public TransportPort getFeedbackPort() {
		return feedback_port;
	}
	
	@Override
	public TransportPort getStatsPort() {
		return stats_port;
	}
	
	public boolean addTransferId(UUID newConnection) {
		return active_transfers.add(newConnection);
	}
	
	public boolean removeTransferId(UUID terminatedConnection) {
		return active_transfers.remove(terminatedConnection);
	}
	
	public boolean isServingTransferId(UUID existingConnection) {
		return active_transfers.contains(existingConnection);
	}
	
	public int getNumTransfersServing() {
		return active_transfers.size();
	}
	
	@Override
	public Set<UUID> getActiveTransfers() {
		return Collections.unmodifiableSet(active_transfers);
	}
	
	@Override
	public String toString() {
		return "SOSAgent [ " + super.toString() + " data_port=" + data_port + ", control_port="
				+ control_port + " feedback_port=" + feedback_port + " stats_port=" + stats_port + "]";
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result
				+ ((control_port == null) ? 0 : control_port.hashCode());
		result = prime * result
				+ ((data_port == null) ? 0 : data_port.hashCode());
		result = prime * result
				+ ((feedback_port == null) ? 0 : feedback_port.hashCode());
		result = prime * result
				+ ((stats_port == null) ? 0 : stats_port.hashCode());
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
		if (feedback_port == null) {
			if (other.feedback_port != null)
				return false;
		} else if (!feedback_port.equals(other.feedback_port))
			return false;
		if (stats_port == null) {
			if (other.stats_port != null)
				return false;
		} else if (!stats_port.equals(other.stats_port))
			return false;
		return true;
	}
}