package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.topology.NodePortTuple;

public class SOSRoutingStrategyFirstHopLastHop implements ISOSRoutingStrategy {

	private static final Logger log = LoggerFactory.getLogger(SOSRoutingStrategyFirstHopLastHop.class);
	private boolean rewriteMacUponRedirection = true;

	/**
	 * Assume the first hop redirection switch can also rewrite L2 addresses
	 */
	public SOSRoutingStrategyFirstHopLastHop() { }

	/**
	 * Set whether or not the first hop redirection switch can also rewrite
	 * L2 addresses. Note that calling with @param rewriteMacUponRedirection
	 * true results in the same behavior as the default constructor.
	 * 
	 * @param rewriteMacUponRedirection true if yes; false if no
	 */
	public SOSRoutingStrategyFirstHopLastHop(boolean rewriteMacUponRedirection) {
		this.rewriteMacUponRedirection = rewriteMacUponRedirection;
	}

	@Override
	public void pushRoute(SOSRoute route, SOSConnection conn) {
		if (route.getRouteType() != SOSRouteType.CLIENT_2_AGENT &&
				route.getRouteType() != SOSRouteType.SERVER_2_AGENT) {
			throw new IllegalArgumentException("Only route types client-to-agent or server-to-agent are supported.");
		}

		int flowCount = 1;
		Set<String> flows = new HashSet<String>();
		List<NodePortTuple> path = route.getRoute().getPath();

		/* src--[p=l, s=A], [s=A, p=m], [p=n, s=B], [s=B, p=o], [p=q, s=C], [s=C, p=r]--dst */
		for (int index = path.size() - 1; index > 0; index -= 2) {
			NodePortTuple in = path.get(index - 1);
			NodePortTuple out = path.get(index);
			if (in.equals(route.getRouteFirstHop())) { /* handles flows 1, 4, 12, 13 */
				/* Perform redirection here */
				OFFactory factory = SOS.switchService.getSwitch(in.getNodeId()).getOFFactory();
				OFFlowAdd.Builder flow = factory.buildFlowAdd();
				Match.Builder match = factory.buildMatch();
				ArrayList<OFAction> actionList = new ArrayList<OFAction>();

				/* Match *from* either client or server */
				match.setExact(MatchField.IN_PORT, in.getPortId());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_SRC, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getSrcDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_SRC, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_SRC, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}
				
				/* 
				 * Redirect to either client-side or server-side agent via L2 rewrite.
				 * This allows for non-OpenFlow switches to be mixed into the network,
				 * which likely run their own learning switch algorithms. Not rewriting
				 * the dst MAC to that of the local agent could result in interesting/
				 * undesirable behavior in a hybrid OpenFlow/non-OpenFlow deployment.
				 */
				if (rewriteMacUponRedirection) {
					if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
						actionList.add(factory.actions().setDlDst(route.getDstDevice().getMACAddr()));
					} else {
						actionList.add(factory.actions().setField(factory.oxms().ethDst(route.getDstDevice().getMACAddr())));
					}
				}
				actionList.add(factory.actions().output(out.getPortId(), 0xffFFffFF));

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				/* This flow handles both flow #1 and flow #13 in the basic SOS diagram */
				String flowName = "sos-" + flowCount++; //TODO make name more specific for this client...maybe make a name-creation class?
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);

				/* ***** Start reverse redirection flow TODO can we reuse code anyplace here? ***** */
				flow = factory.buildFlowAdd();
				match = factory.buildMatch();
				actionList = new ArrayList<OFAction>();

				/* Match *to* either client or server (presumably from an agent) */
				match.setExact(MatchField.IN_PORT, out.getPortId());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_DST, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getSrcDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_DST, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_DST, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}
				
				/* 
				 * L3+L4 destined for client or server, but might have incorrect MAC.
				 * Need to make the destination *think* the packet came from the other
				 * participating device (either server or client)
				 */
				if (rewriteMacUponRedirection) {
					if (route.getSrcDevice() instanceof SOSClient) {
						if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
							actionList.add(factory.actions().setDlSrc(conn.getServer().getMACAddr()));
						} else {
							actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getServer().getMACAddr())));
						}
					} else {
						if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
							actionList.add(factory.actions().setDlSrc(conn.getClient().getMACAddr()));
						} else {
							actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getClient().getMACAddr())));
						}
					}
				}
				actionList.add(factory.actions().output(in.getPortId(), 0xffFFffFF)); /* Reverse, so use "in" */

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				flowName = "sos-" + flowCount++;
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);
			} else if (out.equals(route.getRouteLastHop())) { /* handles flows 2, 3, 11, 14 */
				/* Perform rewrite here */
				OFFactory factory = SOS.switchService.getSwitch(in.getNodeId()).getOFFactory();
				OFFlowAdd.Builder flow = factory.buildFlowAdd();
				Match.Builder match = factory.buildMatch();
				ArrayList<OFAction> actionList = new ArrayList<OFAction>();

				match.setExact(MatchField.IN_PORT, in.getPortId());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_SRC, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getSrcDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_SRC, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_SRC, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}

				if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
					if (!rewriteMacUponRedirection) { 
						actionList.add(factory.actions().setDlDst(route.getDstDevice().getMACAddr()));
					}
					actionList.add(factory.actions().setNwDst(route.getDstDevice().getIPAddr()));
					actionList.add(factory.actions().setTpDst(((SOSAgent) route.getDstDevice()).getDataPort()));
				} else {
					if (!rewriteMacUponRedirection) {
						actionList.add(factory.actions().setField(factory.oxms().ethDst(route.getDstDevice().getMACAddr())));
					}
					actionList.add(factory.actions().setField(factory.oxms().ipv4Dst(route.getDstDevice().getIPAddr())));
					actionList.add(factory.actions().setField(factory.oxms().tcpDst(((SOSAgent) route.getDstDevice()).getDataPort())));
				}

				actionList.add(factory.actions().output(out.getPortId(), 0xffFFffFF));

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				String flowName = "sos-" + flowCount++;
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);

				/* Reverse rewrite flow */
				flow = factory.buildFlowAdd();
				match = factory.buildMatch();
				actionList = new ArrayList<OFAction>();

				match.setExact(MatchField.IN_PORT, out.getPortId());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_DST, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getSrcDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_DST, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_DST, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}

				if (route.getSrcDevice() instanceof SOSClient) {
					if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
						if (!rewriteMacUponRedirection) { 
							actionList.add(factory.actions().setDlSrc(conn.getServer().getMACAddr()));
						}
						actionList.add(factory.actions().setNwSrc(conn.getServer().getIPAddr()));
						actionList.add(factory.actions().setTpSrc(conn.getServer().getTcpPort()));
					} else {
						if (!rewriteMacUponRedirection) {
							actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getServer().getMACAddr())));
						}
						actionList.add(factory.actions().setField(factory.oxms().ipv4Src(conn.getServer().getIPAddr())));
						actionList.add(factory.actions().setField(factory.oxms().tcpSrc(conn.getServer().getTcpPort())));
					}
				} else {
					if (factory.getVersion().compareTo(OFVersion.OF_12) < 0) {
						if (!rewriteMacUponRedirection) { 
							actionList.add(factory.actions().setDlSrc(conn.getClient().getMACAddr()));
						}
						actionList.add(factory.actions().setNwSrc(conn.getClient().getIPAddr()));
						actionList.add(factory.actions().setTpSrc(conn.getClient().getTcpPort()));
					} else {
						if (!rewriteMacUponRedirection) {
							actionList.add(factory.actions().setField(factory.oxms().ethSrc(conn.getClient().getMACAddr())));
						}
						actionList.add(factory.actions().setField(factory.oxms().ipv4Src(conn.getClient().getIPAddr())));
						actionList.add(factory.actions().setField(factory.oxms().tcpSrc(conn.getClient().getTcpPort())));
					}
				}

				actionList.add(factory.actions().output(in.getPortId(), 0xffFFffFF));

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				flowName = "sos-" + flowCount++;
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);
			} else {
				/* Simply forward to next hop from here */
				OFFactory factory = SOS.switchService.getSwitch(in.getNodeId()).getOFFactory();
				OFFlowAdd.Builder flow = factory.buildFlowAdd();
				Match.Builder match = factory.buildMatch();
				ArrayList<OFAction> actionList = new ArrayList<OFAction>();

				match.setExact(MatchField.IN_PORT, in.getPortId());
				match.setExact(MatchField.ETH_SRC, route.getSrcDevice().getMACAddr());
				match.setExact(MatchField.ETH_DST, route.getDstDevice().getMACAddr());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_SRC, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getSrcDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_SRC, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_SRC, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}
				actionList.add(factory.actions().output(out.getPortId(), 0xffFFffFF));

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				String flowName = "sos-" + flowCount++;
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);
				
				/* And now do the reverse flow */
				flow = factory.buildFlowAdd();
				match = factory.buildMatch();
				actionList = new ArrayList<OFAction>();

				match.setExact(MatchField.IN_PORT, out.getPortId());
				match.setExact(MatchField.ETH_DST, route.getSrcDevice().getMACAddr());
				match.setExact(MatchField.ETH_SRC, route.getDstDevice().getMACAddr());
				match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				match.setExact(MatchField.IPV4_DST, route.getSrcDevice().getIPAddr());
				match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
				if (route.getDstDevice() instanceof SOSClient) {
					match.setExact(MatchField.TCP_DST, ((SOSClient) route.getSrcDevice()).getTcpPort());
				} else {
					match.setExact(MatchField.TCP_DST, ((SOSServer) route.getSrcDevice()).getTcpPort());
				}
				actionList.add(factory.actions().output(in.getPortId(), 0xffFFffFF));

				flow.setBufferId(OFBufferId.NO_BUFFER);
				flow.setOutPort(OFPort.ANY);
				flow.setActions(actionList);
				flow.setMatch(match.build());
				flow.setPriority(32767);
				flow.setIdleTimeout(conn.getFlowTimeout());

				flowName = "sos-" + flowCount++;
				SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
				flows.add(flowName);
				log.info("added flow on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId() + flowName);
			}
		}
		conn.addFlows(flows);
	}
}