
package net.floodlightcontroller.traceroute;

import java.util.HashMap;
import java.util.LinkedList;

class Switch
{
	public char color;
	public String MAC;
	public HashMap hm = new HashMap<Integer, Switch>();
	public LinkedList adj_object =  new LinkedList();
	
	public Switch(){
		color='\0';
		MAC="";
	}
	public void setMac(String s)
	{
		MAC=s;
	}
	
	public char getColor() {
		return color;
	}
	
	public void setColor(char color) {
		this.color = color;
	}
	public String getMac()
	{
	   return MAC;
	}
	
	@Override
	public String toString(){
		return ("Mac is - " + MAC);
	}
	
	
}

