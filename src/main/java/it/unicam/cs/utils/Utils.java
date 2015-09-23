/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.utils;

import it.unicam.cs.sp.config.Configuration;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Utils {
	public static String getUTCTime(){
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(new Date());
	}
	
	public static Date stringToDate(String dateTime) throws Exception{
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.parse(dateTime);
	}
	
	public enum LogType{
		requests, responses, general;
	}
	public static void log(String message, Configuration cfg, LogType logType){
		try{
			String filePath = "";
			if(logType == LogType.requests && !cfg.isLogSamlRequestsEnabled())
				return;
			if(logType == LogType.responses && !cfg.isLogSamlResponsesEnabled())
				return;
			if(logType == LogType.responses)
				filePath = cfg.getLogSamlResponsesFilePath();
			if(logType == LogType.requests)
				filePath = cfg.getLogSamlRequestsFilePath();
			if(logType == LogType.general)
				filePath = cfg.getLogFilePath();
			String callerClassName = new Exception().getStackTrace()[1].getClassName();
			IOUtils.writeFile(("\n"+getUTCTime()+" "+callerClassName+"\n"+message).getBytes(), filePath, true);
		}catch(Exception ex){ex.printStackTrace();}
	}
}
