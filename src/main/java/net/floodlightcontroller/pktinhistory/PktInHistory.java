package net.floodlightcontroller.pktinhistory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.forwarding.Forwarding;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PktInHistory implements IFloodlightModule, IOFMessageListener {
	protected IFloodlightProviderService floodlightProvider;
	protected OFFactory myfactory;
	protected static Logger logger;
	protected IPv4 myIP;
	protected TCP tcp;
	protected UDP udp;

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return PktInHistory.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		if(type==OFType.PACKET_IN && name.equalsIgnoreCase(Forwarding.class.getSimpleName()))
			return true;
		else
			return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		logger.info("Get In");
		// TODO Auto-generated method stub
		switch (msg.getType()) {

		case PACKET_IN:
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
					IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			if (eth.getEtherType().equals(EthType.IPv4)) {
				logger.info("IPv4");
				myIP = (IPv4) eth.getPayload();

				if (myIP.getProtocol().equals(IpProtocol.TCP)) {
					tcp = (TCP) myIP.getPayload();
					logger.info("TCP {}", tcp.getDestinationPort());
					if (tcp.getDestinationPort().equals(TransportPort.of(80))) {
						logger.info("We have succeeded");
						logger.info("Get Out");
						return Command.CONTINUE;
					}
				} else if (myIP.getProtocol().equals(IpProtocol.UDP)) {
					logger.info("UDP");
					udp = (UDP) myIP.getPayload();
					TransportPort a = udp.getDestinationPort();
					TransportPort b = TransportPort.of(80);
					a.compareTo(b);
					if (udp.getDestinationPort().equals(TransportPort.of(80))) {
						logger.info("We have succeeded");
						logger.info("Get Out");
						return Command.CONTINUE;

					}
				}
			} else if (eth.getEtherType().equals(EthType.ARP)) {
				logger.info("ARP");
				return Command.CONTINUE;
			}
			break;
		default:
			break;
		}
		logger.info("Dropping");
		return Command.STOP;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(PktInHistory.class);
		this.myfactory = OFFactories.getFactory(OFVersion.OF_13);
		// TODO Auto-generated method stub

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		// TODO Auto-generated method stub

	}
}

