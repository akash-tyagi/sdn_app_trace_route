package net.floodlightcontroller.traceroute;

import java.util.List;
import java.util.Map;

import net.floodlightcontroller.core.IOFSwitch;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class TraceRouteResource extends ServerResource {
	@Get("json")
	public Map<String, List<IOFSwitch>> retrieve() {
		TraceRouteService traceRouteService = (TraceRouteService) getContext()
				.getAttributes()
				.get(TraceRouteService.class.getCanonicalName());

		Map<String, List<IOFSwitch>> map = traceRouteService.getPath();

		return map;
	}
}
