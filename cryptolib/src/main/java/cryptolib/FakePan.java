package cryptolib;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import static cryptolib.Pinblock.pinBlock;

public class FakePan{


    //Input Tsn
    // Output unique fake pan per TSN
    public static byte[] fakePanBlock(int tsn) throws Exception {

        String pan =generatePan(tsn);

        if(pan.length()<12){
            pan = StringUtils.leftPad(pan,12,'0');
        }
        String panData = pan.length()-12 + pan;
        String panBlock = StringUtils.rightPad(panData,32,'0');

        return toByteArray(panBlock);
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


    // Input: PinBlock, FakePanBlock, PinKey
    //Output Iso format 4 block
    public static String isoFormat4(byte[] pinBlock, byte [] panBlock, String pinKey) {
        try {

            final byte[] pinpanblock = new byte[16];
            for (int i = 0; i < 16; i++)
                pinpanblock[i] = (byte) (pinBlock[i] ^ panBlock[i]);

            final byte[] extendedPinblock = Dukpt.encryptAes(toByteArray(pinKey), pinpanblock);
            return Hex.encodeHexString(extendedPinblock).toUpperCase();

        } catch (Exception e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }



    //Same as old method do not copy
    public static byte[] toByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }



    //Main method for demonstrating use
    public static void main(String[] args) throws Exception {
        String pinkey = "A27F07BD25653BA84C38B59A0891989F";
        byte[] pinBlock = pinBlock("1234",pinkey);
        byte[] fakePanBlock = fakePanBlock(100004);


        String iso4 = isoFormat4(pinBlock,fakePanBlock,pinkey);

    }
}