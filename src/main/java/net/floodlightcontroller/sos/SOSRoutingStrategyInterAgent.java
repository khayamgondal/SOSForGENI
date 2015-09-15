package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
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

public class SOSRoutingStrategyInterAgent implements ISOSRoutingStrategy {

	private static final Logger log = LoggerFactory.getLogger(SOSRoutingStrategyInterAgent.class);

	@Override
	public void pushRoute(SOSRoute route, SOSConnection conn) {
		if (route.getRouteType() != SOSRouteType.AGENT_2_AGENT) {
			throw new IllegalArgumentException("Only route type agent-to-agent is supported.");
		}
		
		int flowCount = conn.getFlowNames().size() + 1;
		String flowNamePrefix = "sos-ia-" + conn.getName() + "-#";
		Set<String> flows = new HashSet<String>();
		List<NodePortTuple> path = route.getRoute().getPath();

		/* src--[p=l, s=A], [s=A, p=m], [p=n, s=B], [s=B, p=o], [p=q, s=C], [s=C, p=r]--dst */
		for (int index = path.size() - 1; index > 0; index -= 2) {
			NodePortTuple in = path.get(index - 1);
			NodePortTuple out = path.get(index);
			
			OFFactory factory = SOS.switchService.getSwitch(in.getNodeId()).getOFFactory();
			OFFlowAdd.Builder flow = factory.buildFlowAdd();
			Match.Builder match = factory.buildMatch();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();

			/* Match *from* client-side agent */
			match.setExact(MatchField.IN_PORT, in.getPortId());
			match.setExact(MatchField.ETH_SRC, route.getSrcDevice().getMACAddr());
			match.setExact(MatchField.ETH_DST, route.getDstDevice().getMACAddr());
			match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match.setExact(MatchField.IPV4_SRC, route.getSrcDevice().getIPAddr());
			match.setExact(MatchField.IPV4_DST, route.getDstDevice().getIPAddr());
			match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
			//TODO we could match on specific TCP ports (of the || connections), but they're not so deterministic at present
			
			actionList.add(factory.actions().output(out.getPortId(), 0xffFFffFF));

			flow.setBufferId(OFBufferId.NO_BUFFER);
			flow.setOutPort(OFPort.ANY);
			flow.setActions(actionList);
			flow.setMatch(match.build());
			flow.setPriority(32767);
			flow.setIdleTimeout(conn.getFlowTimeout());

			String flowName = flowNamePrefix + flowCount++;
			SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
			flows.add(flowName);
			log.info("Added inter-agent flow {}, {} on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId(), flowName, flow);
			
			flow = factory.buildFlowAdd();
			match = factory.buildMatch();
			actionList = new ArrayList<OFAction>();

			/* Match *from* server-side agent */
			match.setExact(MatchField.IN_PORT, out.getPortId());
			match.setExact(MatchField.ETH_DST, route.getSrcDevice().getMACAddr());
			match.setExact(MatchField.ETH_SRC, route.getDstDevice().getMACAddr());
			match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match.setExact(MatchField.IPV4_DST, route.getSrcDevice().getIPAddr());
			match.setExact(MatchField.IPV4_SRC, route.getDstDevice().getIPAddr());
			match.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
			//TODO we could match on specific TCP ports (of the || connections), but they're not so deterministic at present
			
			actionList.add(factory.actions().output(in.getPortId(), 0xffFFffFF));

			flow.setBufferId(OFBufferId.NO_BUFFER);
			flow.setOutPort(OFPort.ANY);
			flow.setActions(actionList);
			flow.setMatch(match.build());
			flow.setPriority(32767);
			flow.setIdleTimeout(conn.getFlowTimeout());

			flowName = flowNamePrefix + flowCount++;
			SOS.sfp.addFlow(flowName, flow.build(), SOS.switchService.getSwitch(in.getNodeId()).getId());
			flows.add(flowName);
			log.info("Added inter-agent flow {}, {} on SW " + SOS.switchService.getSwitch(in.getNodeId()).getId(), flowName, flow);
		}
		
		/* 
		 * Update the list of flows names for this connection
		 * s.t. we can remove them later if needed.
		 */
		conn.addFlows(flows);
	}
}