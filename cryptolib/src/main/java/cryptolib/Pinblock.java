package cryptolib;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import java.util.Random;


public class Pinblock {
	public static void main(String[] args) throws Exception {
		String pinkey = "ED37594B6DEB53BFBEBA7A573DBA6D5D";
		String panKey = "A27F07BD25653BA84C38B59A12345678";
		String pan = "1300012133";
		byte[] pinBlock = pinBlock("1234",pinkey);
		byte[] fakePanBlock = fakePanBlock(210000);
		byte[] encryptedPan = Dukpt.encryptAes(toByteArray(panKey),toByteArray(pan),true);


		String iso4 = isoFormat4(pinBlock,fakePanBlock,pinkey);

	String test = 	migrateFakePinToIso0(toByteArray(iso4),encryptedPan,toByteArray(pinkey),toByteArray(panKey),100004);



	}

	private static String getRandomHexString(int numchars){
		Random r = new Random();
		StringBuffer sb = new StringBuffer();
		while(sb.length() < numchars){
			sb.append(Integer.toHexString(r.nextInt()));
		}

		return sb.toString().substring(0, numchars);
	}

	public static byte[] pinBlock(String pin, String pinKey) throws Exception {
		String pinData = "4"+pin.length() + pin;
		String pinBlock =  StringUtils.rightPad(pinData,16,'A');
		pinBlock += getRandomHexString(16);
		byte[] pBlock= Dukpt.encryptAes(toByteArray(pinKey),toByteArray(pinBlock));
		return  pBlock;
	}



	public static String generatePan(int id){
		int [] denomination = {26, 10, 10, 10, 10, 26, 26, 26, 26, 26};
		int current = id;

		String finalS = "";
		for (int i  = 0 ; i < 10 ; i++)
		{
			int part  = current % denomination[i];
			String temp1 =  Character.toString((char) (65+part)) ;
			String temp2 = Character.toString((char)( part+'0'));
			String charPart = (denomination[i] == 26 ? temp1 : temp2);

			finalS =  charPart + finalS ;
			current = current/denomination[i];
		}
		return finalS;
	}

	public static byte[] fakePanBlock(int tsn) throws Exception {

		String pan =generatePan(tsn);

		if(pan.length()<12){
			pan = StringUtils.leftPad(pan,12,'0');
		}
		String panData = pan.length()-12 + pan;
		String panBlock = StringUtils.rightPad(panData,32,'0');

		return toByteArray(panBlock);
	}
	public static byte[] toByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static String isoFormat4(byte[] bPin, byte [] panBlock, String pinKey) {
		try {

			final byte[] pinpanblock = new byte[16];
			for (int i = 0; i < 16; i++)
				pinpanblock[i] = (byte) (bPin[i] ^ panBlock[i]);

			final byte[] extendedPinblock = Dukpt.encryptAes(toByteArray(pinKey), pinpanblock);
			return Hex.encodeHexString(extendedPinblock).toUpperCase();

		} catch (Exception e) {
			throw new RuntimeException("Hex decoder failed!", e);
		}
	}

	public static String migrateFakePinToIso0(byte[] fakePinBlock, byte[] encryptedPan, byte[] pinKey, byte[] panKey,int tsn) throws Exception {

		byte[] fakePan = fakePanBlock(tsn);
		byte[] rawPan = Dukpt.decryptAes(panKey,encryptedPan,true);

		byte[] blockB = Dukpt.decryptAes(pinKey,fakePinBlock);

		final byte[] blockA = new byte[16];
		for (int i = 0; i < 16; i++)
			blockA[i] = (byte) (blockB[i] ^ fakePan[i]);


		byte[] rawPin = Dukpt.decryptAes(pinKey,blockA);
		String pinBlock = Hex.encodeHexString(rawPin);
		int pinLength = Character.getNumericValue( pinBlock.charAt(1) );
		String pin = pinBlock.substring(2, 2+pinLength);

//		byte[] rawPanShrink = new String(rawPan, 0, 8).getBytes();
		String tt = Hex.encodeHexString(rawPan);
		byte[] panBlockIso0 = generatePanBlock(Hex.encodeHexString(rawPan));
		String pinPanBlockIso0 = generatePinPanBlock(pin,panBlockIso0,pinKey);
		System.out.println(pinPanBlockIso0);
		return pinPanBlockIso0;

	}

	public static byte[] generatePanBlock(String pan) throws DecoderException {
		String panPart = null;
		if (pan.length() > 12)
			panPart = pan.substring(pan.length() - 13, pan.length() - 1);
		else
			panPart = pan;
		final String panData = StringUtils.leftPad(panPart, 16, '0');
		System.out.print("pan "+panData);
		final byte[] bPan = Hex.decodeHex(panData.toCharArray());
		return bPan;
	}

	public static String generatePinPanBlock(String pin, byte[] pan,byte[] PinKey) throws DecoderException {

		final String pinLenHead = StringUtils.leftPad(Integer.toString(pin.length()), 2, '0') + pin;
		final String pinData = StringUtils.rightPad(pinLenHead, 16, 'F');
		final byte[] bPin = Hex.decodeHex(pinData.toCharArray());

		final byte[] pinblock = new byte[8];
		for (int i = 0; i < 8; i++)
			pinblock[i] = (byte) (bPin[i] ^ pan[i]);

		byte[] extendedPinblock = new byte[0];
		String h = Hex.encodeHexString(bPin) + "\n" + Hex.encodeHexString(pan);
		try{

			extendedPinblock = Dukpt.encryptTripleDes( PinKey,pinblock);

		}catch (Exception e){
			e.printStackTrace();

		}

		return Hex.encodeHexString(extendedPinblock).toUpperCase();

	}
}