package net.floodlightcontroller.sos;

import javax.annotation.Nonnull;

import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;

public class SOSRoute {
	private SOSDevice d1;
	private SOSDevice d2;
	private Route route;
	private NodePortTuple d1_sp;
	private NodePortTuple d2_sp;
	private SOSRouteType t;
	
	public SOSRoute(@Nonnull SOSDevice src, @Nonnull SOSDevice dst, @Nonnull Route route) {
		if (src == null) {
			throw new IllegalArgumentException("SOSDevice src cannot be null");
		} else if (dst == null) {
			throw new IllegalArgumentException("SOSDevice dst cannot be null");
		} else if (route == null) {
			throw new IllegalArgumentException("Route cannot be null");
		}
		
		if (route.getPath().isEmpty()) {
			throw new IllegalArgumentException("Route cannot be empty -- must contain at least one OpenFlow switch");
		}
		
		if (src == dst || src.equals(dst)) {
			throw new IllegalArgumentException("SOSDevice src and dst cannot be equal");
		}
		
		this.d1 = src;
		this.d2 = dst;
		
		/* Set the first and last hops */
		this.d1_sp = route.getPath().get(0);
		this.d2_sp = route.getPath().get(route.getPath().size() - 1); /* guaranteed to be at least 1 in length (element 0) */
		
		if (d1 instanceof SOSClient && d2 instanceof SOSAgent) {
			this.t = SOSRouteType.CLIENT_2_AGENT;
		} else if (d1 instanceof SOSAgent && d2 instanceof SOSAgent) {
			this.t = SOSRouteType.AGENT_2_AGENT;
		} else if (d1 instanceof SOSServer && d2 instanceof SOSAgent) {
			this.t = SOSRouteType.SERVER_2_AGENT;
		} else {
			throw new IllegalArgumentException("SOSRoute must go from client-to-agent, server-to-agent, or agent-to-agent.");
		}
		this.route = route;
	}
	
	public SOSDevice getSrcDevice() {
		return d1;
	}
	
	public SOSDevice getDstDevice() {
		return d2;
	}
	
	public NodePortTuple getRouteFirstHop() {
		return d1_sp;
	}
	
	public NodePortTuple getRouteLastHop() {
		return d2_sp;
	}
		
	public Route getRoute() {
		return route;
	}
	
	public SOSRouteType getRouteType() {
		return t;
	}

	@Override
	public String toString() {
		return "SOSRoute [d1=" + d1 + ", d2=" + d2 + ", route=" + route
				+ ", t=" + t + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((d1 == null) ? 0 : d1.hashCode());
		result = prime * result + ((d2 == null) ? 0 : d2.hashCode());
		result = prime * result + ((route == null) ? 0 : route.hashCode());
		result = prime * result + ((t == null) ? 0 : t.hashCode());
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
		SOSRoute other = (SOSRoute) obj;
		if (d1 == null) {
			if (other.d1 != null)
				return false;
		} else if (!d1.equals(other.d1))
			return false;
		if (d2 == null) {
			if (other.d2 != null)
				return false;
		} else if (!d2.equals(other.d2))
			return false;
		if (route == null) {
			if (other.route != null)
				return false;
		} else if (!route.equals(other.route))
			return false;
		if (t != other.t)
			return false;
		return true;
	}
}