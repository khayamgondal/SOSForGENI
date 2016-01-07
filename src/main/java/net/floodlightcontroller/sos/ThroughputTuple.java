package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.U64;

/**
 * Container for rolling and cumulative throughput. Mainly
 * for use in storing SOS active transfer stats.
 * 
 * @author Ryan Izard, rizard@g.clemson.edu
 */
public class ThroughputTuple {
	private U64 cumulative_throughput;
	private U64 rolling_throughput;
	
	private ThroughputTuple(U64 cumulative, U64 rolling) { 
		cumulative_throughput = cumulative;
		rolling_throughput = rolling;
	}
	
	public static ThroughputTuple of(U64 cumulative, U64 rolling) {
		if (cumulative == null) {
			throw new IllegalArgumentException("Cumulative throughput cannot be null");
		}
		if (rolling == null) {
			throw new IllegalArgumentException("Rolling throughput cannot be null");
		}
		
		return new ThroughputTuple(cumulative, rolling);
	}
	
	public U64 getCumulativeThroughput() {
		return cumulative_throughput;
	}
	
	public U64 getRollingThroughput() {
		return rolling_throughput;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime
				* result
				+ ((cumulative_throughput == null) ? 0 : cumulative_throughput
						.hashCode());
		result = prime
				* result
				+ ((rolling_throughput == null) ? 0 : rolling_throughput
						.hashCode());
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
		ThroughputTuple other = (ThroughputTuple) obj;
		if (cumulative_throughput == null) {
			if (other.cumulative_throughput != null)
				return false;
		} else if (!cumulative_throughput.equals(other.cumulative_throughput))
			return false;
		if (rolling_throughput == null) {
			if (other.rolling_throughput != null)
				return false;
		} else if (!rolling_throughput.equals(other.rolling_throughput))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ThroughputTuple [cumulative_throughput="
				+ cumulative_throughput + ", rolling_throughput="
				+ rolling_throughput + "]";
	}
}