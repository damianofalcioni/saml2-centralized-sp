/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.sp.background;

import it.unicam.cs.sp.config.Configuration;
import it.unicam.cs.utils.AGIDUtils;
import it.unicam.cs.utils.IOUtils;
import it.unicam.cs.utils.NETUtils;
import it.unicam.cs.utils.Utils;
import it.unicam.cs.utils.Utils.LogType;


public class UpdateFederatedMetadatasTask implements Runnable {
	
	private static int minutesOfInterval = 60 * 12;
	private Configuration cfg = null;
	
	public UpdateFederatedMetadatasTask(Configuration cfg){
		this.cfg = cfg;
	}
	
	public void process() throws Exception{
		if(cfg == null)
			throw new Exception("cfg is null");
		String[] fedIdToUpdateList = cfg.getFederationToUpdate();
		for(String fedIdToUpdate:fedIdToUpdateList){
			String remoteURL = cfg.getRemoteFederationMetadataURI(fedIdToUpdate);
			if(remoteURL.isEmpty())
				continue;
			String localFile = cfg.getLocalFederationMetadataURI(fedIdToUpdate);
			byte[] metadataContent = NETUtils.sendHTTPGET(remoteURL, null, false, false);
			IOUtils.writeFile(metadataContent, localFile, false);
		}
		String agidUri = cfg.getAgidRegistryURI();
		if(!agidUri.isEmpty() && cfg.isAgidRegistryEnabled()){
			String metadataContent = AGIDUtils.generateFederatedMetadata(agidUri);
			String localFile = cfg.getLocalFederationMetadataURI("agid");
			IOUtils.writeFile(metadataContent.getBytes(), localFile, false);
		}
	}
	
	public void run() {
		while(true){
			try{
				process();
			}catch(Exception ex){ex.printStackTrace(); Utils.log(ex.getMessage(), cfg, LogType.general);}
			try {
				Thread.sleep(1000*60*minutesOfInterval);
			} catch (InterruptedException e) {e.printStackTrace(); Utils.log(e.getMessage(), cfg, LogType.general);}
		}
	}
	
	public static void main(String[] args) throws Exception {
		UpdateFederatedMetadatasTask t = new UpdateFederatedMetadatasTask(new Configuration());
		t.run();
	}
}