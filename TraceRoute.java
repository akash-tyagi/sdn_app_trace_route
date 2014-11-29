package net.floodlightcontroller.traceroute;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.traceroute.Switch.Color;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionVirtualLanIdentifier;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TraceRoute implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 60; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	private static int count = 0;
	private static final short VLANID_WHITE = -1;
	private static final short VLANID_BLACK = 1;
	private static boolean isColoringInitialized = false;

	class HostInfo {
		int sourceIp;
		short port;
	}

	protected Map<Integer, Long> ipToSwitchId;
	protected Map<Long, Map<Integer, HostInfo>> switchToHostsInfo;
	protected static Map<Switch, IOFSwitch> switchToIOFSwitchMap;
	protected static Map<String, String> hostMacToSwitchMacMap;
	protected Map<String, List<IOFSwitch>> path;

	@Override
	public String getName() {
		return TraceRoute.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
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
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		ipToSwitchId = new HashMap<>();
		switchToHostsInfo = new HashMap<>();
		logger = LoggerFactory.getLogger(TraceRoute.class);
		switchToIOFSwitchMap = new ConcurrentHashMap<Switch, IOFSwitch>();
		hostMacToSwitchMacMap = new ConcurrentHashMap<String, String>();
		path = new ConcurrentHashMap<String, List<IOFSwitch>>();
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		logger.info("--------------------------------------------------------");
		switch (msg.getType()) {
		case PACKET_IN:
			logger.info("PacketIn Path...");
			return processPacketInMessage(sw, (OFPacketIn) msg, cntx);
		default:
			break;
		}

		return Command.CONTINUE;
	}

	private net.floodlightcontroller.core.IListener.Command processPacketInMessage(
			IOFSwitch iofSwitch, OFPacketIn msg, FloodlightContext cntx) {
		System.out.println("-----------------------------Count:" + count++);

		if (!isColoringInitialized) {
			Graph g = new Graph();
			g.initializeTopology();
			TwoNodeColoring b = new TwoNodeColoring();
			b.StartTwoNodeColoring(g);
			isColoringInitialized = true;
		}
		OFPacketIn pi = (OFPacketIn) msg;
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		int destIP = match.getNetworkDestination();
		int sourceIP = match.getNetworkSource();
		Short inputPort = pi.getInPort();
		long swId = iofSwitch.getId();

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress());

		if (match.getDataLayerType() == Ethernet.TYPE_IPv4
				&& match.getNetworkProtocol() == IPv4.PROTOCOL_ICMP) {
			String dpid = HexString.toHexString(iofSwitch.getId());
			String sMac = HexString.toHexString(sourceMACHash);
			System.out.println("dpid:" + dpid + " mac:" + sMac);
			Switch swtch = Graph.mac_to_switch_object.get(dpid);
			if (swtch == null) {
				System.out.println("WTF!!!!!!!!!!!!!!!!!!!");
			}
			if (!switchToIOFSwitchMap.containsValue(iofSwitch)) {
				switchToIOFSwitchMap.put(swtch, iofSwitch);
			}

			if (!hostMacToSwitchMacMap.containsKey(sMac)) {
				hostMacToSwitchMacMap.put(sMac, dpid);
			}

			String packetId = sourceIP + ":" + destIP;
			if (!path.containsKey(packetId)) {
				path.put(packetId, new ArrayList<IOFSwitch>());
			}
		}

		// If sourceIP is discovered for the first time, store in map
		if (!ipToSwitchId.containsKey(sourceIP)) {
			ipToSwitchId.put(sourceIP, iofSwitch.getId());
		}

		if (destIP != 0) {
			if (!switchToHostsInfo.containsKey(swId)) {
				Map<Integer, HostInfo> map = new HashMap<>();
				switchToHostsInfo.put(swId, map);
			}
			if (!switchToHostsInfo.get(swId).containsKey(sourceIP)) {
				HostInfo info = new HostInfo();
				info.sourceIp = sourceIP;
				info.port = inputPort;
				switchToHostsInfo.get(swId).put(sourceIP, info);
			}

			// If dest IP is already discovered then install the forward and
			// reverse rules
			if (switchToHostsInfo.get(swId).containsKey(destIP)) {
				OFMatch reverseMatch = match
						.clone()
						.setDataLayerSource(match.getDataLayerDestination())
						.setDataLayerDestination(match.getDataLayerSource())
						.setNetworkSource(match.getNetworkDestination())
						.setNetworkDestination(match.getNetworkSource())
						.setInputPort(
								switchToHostsInfo.get(iofSwitch.getId()).get(
										match.getNetworkDestination()).port);
				if (match.getDataLayerType() == Ethernet.TYPE_ARP) {
					installRule(iofSwitch, match);
					installRule(iofSwitch, reverseMatch);
				} else if (match.getDataLayerType() == Ethernet.TYPE_IPv4
						&& match.getNetworkProtocol() == IPv4.PROTOCOL_ICMP) {
					int vlanId = 1;
					Switch swtch = Graph.mac_to_switch_object.get(iofSwitch
							.getId());
					Color color = swtch.getColor();
					System.out.println("Color:" + color.toString());
					System.out.print("hurray" + swtch.getColor());

					// // For white, forward packet with vlan changes to -1
					// // (default) and forward
					// if (color.equals(Color.WHITE)) {
					// vlanId = VLANID_WHITE;
					// // installRuleForIcmp(iofSwitch, match, vlanId);
					// // installRuleForIcmp(iofSwitch, reverseMatch, vlanId);
					// } else if (color.equals(Color.BLACK)) {
					//
					// } else {
					// System.out
					// .println("Color not available on the node please check algorithm again");
					// }

					installRuleForIcmp(iofSwitch, match, vlanId);
					installRuleForIcmp(iofSwitch, reverseMatch, vlanId);
				}
			}
		}
		// Flood the packet
		System.out.println("flooding-----");
		this.pushPacket(iofSwitch, match, pi,
				(short) OFPort.OFPP_FLOOD.getValue());
		return Command.CONTINUE;
	}

	private void installRuleForIcmp(IOFSwitch sw, OFMatch match, int vlanId) {
		short outPort = switchToHostsInfo.get(sw.getId()).get(
				match.getNetworkDestination()).port;
		System.out.println("Output port:" + outPort);
		System.out.println("Vlan:" + match.getDataLayerVirtualLan());

		// create the rule
		OFFlowMod rule = (OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		// set the Flow Removed bit
		rule.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);

		// set of actions to apply to this rule
		int len = 0;
		ArrayList<OFAction> actions = new ArrayList<OFAction>();

		OFActionVirtualLanIdentifier action = new OFActionVirtualLanIdentifier();
		action.setVirtualLanIdentifier((short) 1);
		actions.add(action);

		OFAction outputTo = new OFActionOutput(
				OFPort.OFPP_CONTROLLER.getValue());
		actions.add(outputTo);

		len = OFActionOutput.MINIMUM_LENGTH
				+ OFActionVirtualLanIdentifier.MINIMUM_LENGTH;
		setBasicPropForRule(rule, len);

		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.IN_PORT).matchOn(Flag.NW_PROTO).withNwSrcMask(32)
				.withNwDstMask(32));
		sendFlowMod(sw, rule, actions, match);
	}

	private void installRuleForBlack(IOFSwitch sw, OFMatch match, int vlanId) {
		short outPort2 = switchToHostsInfo.get(sw.getId()).get(
				match.getNetworkDestination()).port;
		System.out.println("Output port:" + outPort2);
		System.out.println("Vlan:" + match.getDataLayerVirtualLan());

		// create the rule
		OFFlowMod rule1 = (OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		OFFlowMod rule2 = (OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		// set the Flow Removed bit
		rule1.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);
		rule2.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);

		// set of actions to apply to this rule
		int len1 = 0, len2 = 0;
		ArrayList<OFAction> actions1 = new ArrayList<OFAction>();
		ArrayList<OFAction> actions2 = new ArrayList<OFAction>();

		OFActionVirtualLanIdentifier action1 = new OFActionVirtualLanIdentifier();
		action1.setVirtualLanIdentifier((short) VLANID_BLACK);
		actions1.add(action1);

		OFAction outputTo1 = new OFActionOutput(
				OFPort.OFPP_CONTROLLER.getValue());
		actions1.add(outputTo1);

		OFActionVirtualLanIdentifier action2 = new OFActionVirtualLanIdentifier();
		action2.setVirtualLanIdentifier((short) VLANID_WHITE);
		actions2.add(action2);

		OFAction outputTo2 = new OFActionOutput(outPort2);
		actions2.add(outputTo2);

		len1 = len2 = OFActionOutput.MINIMUM_LENGTH
				+ OFActionVirtualLanIdentifier.MINIMUM_LENGTH;
		setBasicPropForRule(rule1, len1);
		setBasicPropForRule(rule2, len2);

		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.DL_VLAN).matchOn(Flag.IN_PORT)
				.matchOn(Flag.NW_PROTO).withNwSrcMask(32).withNwDstMask(32));
		sendFlowMod(sw, rule1, actions1, match);
		sendFlowMod(sw, rule2, actions2, match);
	}

	private void installRule(IOFSwitch sw, OFMatch match) {
		short outPort = switchToHostsInfo.get(sw.getId()).get(
				match.getNetworkDestination()).port;
		System.out.println("Output port:" + outPort);

		// create the rule
		OFFlowMod rule = (OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		// set the Flow Removed bit
		rule.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);

		// set of actions to apply to this rule
		int len = 0;
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFAction outputTo = new OFActionOutput(outPort);
		actions.add(outputTo);

		len = OFActionOutput.MINIMUM_LENGTH;
		setBasicPropForRule(rule, len);

		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.IN_PORT).withNwSrcMask(32).withNwDstMask(32));
		sendFlowMod(sw, rule, actions, match);
	}

	private void sendFlowMod(IOFSwitch sw, OFFlowMod rule,
			ArrayList<OFAction> actions, OFMatch match) {
		rule.setMatch(match);
		rule.setActions(actions);

		try {
			sw.write(rule, null);
			logger.info("Rule installation successfull From:"
					+ match.getNetworkSource() + " to "
					+ match.getNetworkDestination() + " on sw:" + sw.getId());
		} catch (Exception e) {
			logger.error("Rule installation failed");
			e.printStackTrace();
		}
	}

	private void setBasicPropForRule(OFFlowMod rule, int len) {
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		// specify timers for the life of the rule
		rule.setIdleTimeout(TraceRoute.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		rule.setHardTimeout(TraceRoute.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + len));
	}

	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi,
			short outport) {

		// create an OFPacketOut for the pushed packet
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);

		// update the inputPort and bufferID
		po.setInPort(pi.getInPort());
		po.setBufferId(pi.getBufferId());

		// define the actions to apply for this packet
		OFActionOutput action = new OFActionOutput();
		action.setPort(outport);
		po.setActions(Collections.singletonList((OFAction) action));
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// set data if it is included in the packet in but buffer id is NONE
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength() + packetData.length));
			po.setPacketData(packetData);
		} else {
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength()));
		}

		// push the packet to the switch
		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("failed to write packetOut: ", e);
		}
	}

}