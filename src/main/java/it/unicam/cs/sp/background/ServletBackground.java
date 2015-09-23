/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.background;

import it.unicam.cs.sp.config.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class ServletBackground implements ServletContextListener {

	private ExecutorService executor;
	private Configuration cfg = null;

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		try{
			cfg = new Configuration(arg0.getServletContext().getInitParameter("configFile"));
		}catch(Exception ex){}
		executor = Executors.newSingleThreadExecutor();
        executor.submit(new UpdateFederatedMetadatasTask(cfg));
	}
	
	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		executor.shutdown();
	}
}
