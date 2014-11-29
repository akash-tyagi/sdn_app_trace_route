package net.floodlightcontroller.traceroute;

import java.util.List;
import java.util.Map;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface TraceRouteService extends IFloodlightService {
	public Map<String, List<IOFSwitch>> getPath();
}
