/*
 * Created by Damiano Falcioni  contact: damiano.falcioni@gmail.com
 */
package it.unicam.cs.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class IOUtils {

	public static void writeFile(byte[] data, String filePath, boolean appendData) throws Exception{
		FileOutputStream fos = new FileOutputStream(new File(filePath), appendData);
		fos.write(data);
		fos.flush();
		fos.close();
	}
	
	public static byte[] readFile(String file) throws Exception{
		return readFile(new File(file));
	}
	
	public static byte[] readFile(File file) throws Exception{
		RandomAccessFile raf = new RandomAccessFile(file, "r");
		byte[] ret = new byte[(int)raf.length()];
		raf.read(ret);
		raf.close();
		return ret;
	}
	
	public static void copyInputStreamToOutputStream(InputStream input, OutputStream output) throws Exception{
		int n = 0;
		int DEFAULT_BUFFER_SIZE = 1024 * 1024 * 10;
		byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
		while (-1 != (n = input.read(buffer)))
			output.write(buffer, 0, n);
	}
	
	public static byte[] toByteArray(InputStream is) throws Exception{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		copyInputStreamToOutputStream(is, out);
		byte[] ret = out.toByteArray();
		out.close();
		out = null;
	    return ret;
	}
	
	public static byte[] compressToDeflate(byte[] raw) throws Exception {
		ByteArrayOutputStream outB = new ByteArrayOutputStream();
		DeflaterOutputStream dout = new DeflaterOutputStream(outB, new Deflater(9, true));
		dout.write(raw);
		dout.flush();
		dout.close();
		
		byte[] ret = outB.toByteArray();
		return ret;
	}
	
	public static byte[] uncompressFromDeflate(byte[] compressed) throws Exception {
		InputStream in = new InflaterInputStream(new ByteArrayInputStream(compressed), new Inflater(true));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		copyInputStreamToOutputStream(in, out);
		byte[] ret = out.toByteArray();
		in.close();
		out.close();
		return ret;
	}
	
	//Memory efficient read from InputStream
	public static byte[] toByteArrayEfficient(InputStream is) throws Exception{
		
		int totEstimatedLength = is.available();
		int DEFAULT_BUFFER_SIZE = totEstimatedLength;
		if(DEFAULT_BUFFER_SIZE == 0)
			DEFAULT_BUFFER_SIZE =  1024 * 1024 * 10;
		
		byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
		int totLength = 0;
		int tmpLength = 0;
		byte[] ret = new byte[0];

		while (-1 != (tmpLength = is.read(buffer))){
			if(totEstimatedLength != 0 && tmpLength == totEstimatedLength) //Se � vera verr� fatta solo al primo ciclo e non verranno creati ulteriori array, minimizzando la memoria usata.
				return buffer;
			
			totLength += tmpLength;
			byte[] newRet = new byte[totLength];
			System.arraycopy(ret, 0, newRet, 0, ret.length);
			System.arraycopy(buffer, 0, newRet, ret.length, tmpLength);
			ret = newRet;
			System.gc();
		}
		
		System.gc();
		
		return ret;
	}

	public static byte[] doZip(ArrayList<byte[]> filesToZip, ArrayList<String> fileNames) throws Exception{
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ZipOutputStream zos = new ZipOutputStream(output);
		zos.setLevel(9);
		for(int i=0;i<filesToZip.size();i++){
			CRC32 crc = new CRC32();
			byte[] buf = filesToZip.get(i);
			ZipEntry entry = new ZipEntry(fileNames.get(i));
            entry.setSize((long)buf.length);
            crc.reset();
            crc.update(buf);
            entry.setCrc( crc.getValue());
            zos.putNextEntry(entry);
            zos.write(buf, 0, buf.length);
		}
		zos.finish();
		zos.close();
		byte[] ret = output.toByteArray();
		output.close();
		return ret;
	}
	/*
	public static void main(String args[]) {
		//byte[] test = toByteArray(new java.io.FileInputStream("C:\\users\\mio\\desktop\\fulltext.pdf"));
		//writeFile(test, "C:\\users\\mio\\desktop\\cloooone.pdf", false);
		//System.out.println(test.length);
		try{
			//System.out.println(new String(IOUtils.compressToDeflate("ciao".getBytes())));
			String test = "fZJBj5swEIX/CvIdbGigxAqR0k2rRtrs0pDtoZfKMcPGkrGpx1Tbf18Du9X2kuv4zTdv3niDotcD343+ak7wawT00UuvDfL5oSKjM9wKVMiN6AG5l7zZHe95ljA+OOuttJpEO0RwXllzZw2OPbgG3G8l4el0X5Gr9wOnVFsp9NWi5yUrGW3qozDiGRy9e3xono6fTwHjvVOX0cOCUeb5lXMwLbxUJCXRPjhURkyzFjIGtGqHRGIyGiVFnyg/FWhw1ykNdLKb0RO0yoH0tGkeSfTFOgnz0hXphEYg0WFfkZ8FW+dF3mXxui3LeAUti0VRrON8lV1YCoKtWhmkiGOwhF4YX5GMpXnMijhl5zTjecnZx+RDmv4gUf2azydl2rDL7TAviwj51/O5jt/skug7OJyXDSKy3Uxn4bMB9+5Qt9Hi7Tpki0O/pL6h70gLduAPofWwr61W8s+UUS/8bfJUUW3czVLunTCowATXTT2xvo1Cq06Bq8i/wYRul9n//7rtXw==";
			String orig = new String(IOUtils.uncompressFromDeflate(Base64Fast.decode(test)));
			System.out.println(orig);
		}catch(Exception ex){ex.printStackTrace();}
	}
	*/
}
