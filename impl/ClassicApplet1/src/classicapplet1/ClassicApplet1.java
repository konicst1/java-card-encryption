package classicapplet1;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 *
 * @author konicst1
 */
public class ClassicApplet1 extends Applet {
    
    byte jmeno[] = {'S', 't', 'e', 'p', 'a', 'n'};
    byte pole[] = new byte[128];
    short delka_pole = 0;
    short total_offset = 0;
    OwnerPIN pin;
    
    private static final short PIN_LENGTH = 4;
    private static final short VERIFICATION_FAIL = 0x6300;
    private static final short VERIFICATION_SUCCESS = (short) 0x9000;
    private static final short PIN_VERIFICATION_REQUIRED = 0x6301;
    
    byte key_enc_data[] = {0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44};
    byte aes_iv[] = {0x61, 0x22, 0x23, 0x66, 0x11, 0x12, 0x38, 0x14, 0x10, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44};
    byte mac_sig_key_data[] = {0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x61, 0x22, 0x23, 0x66, 0x11, 0x12, 0x38, 0x14, 0x10, 0x22};
    byte mac_sig_iv[] = {0x61, 0x12, 0x23, 0x66, 0x11, 0x12, 0x38, 0x14, 0x33, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44};
    AESKey enc_key;
    AESKey mac_sig_key;
    
    Cipher aes_cipher;
    Signature mac_sig;

    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClassicApplet1(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected ClassicApplet1(byte[] bArray, short bOffset, byte bLength) {
        enc_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        enc_key.setKey(key_enc_data, (short) 0);
        
        mac_sig_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mac_sig_key.setKey(mac_sig_key_data, (short) 0);
        
        aes_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        mac_sig = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        
        pin = new OwnerPIN((byte) 3, (byte) PIN_LENGTH);
        total_offset = bOffset;
        total_offset += bArray[bOffset];  //+ iLen
        total_offset += bArray[(short) (total_offset + 1)];
        total_offset += 3; //skip 3 bytes with len values

        pin.update(bArray, total_offset, (byte) (bLength - total_offset));
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     */
    public void process(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(VERIFICATION_FAIL);
        }
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];
        byte lc = buf[ISO7816.OFFSET_LC];
        byte le = buf[ISO7816.OFFSET_EXT_CDATA];
        if (selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        
        if (cla != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED); //6e00
        }
        
        switch (ins) {
            case 0x01:
                if (verified()) {
                    delka_pole = readData(apdu);
                    ISOException.throwIt(ISO7816.SW_NO_ERROR);
                }
                break;
            case 0x02:
                if (verified()) {
                    sendData(apdu, delka_pole);
                    ISOException.throwIt(ISO7816.SW_NO_ERROR);
                }
                break;
            case 0x00:
                sayMyName(apdu);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case 0x20:
                if (verifyPin(apdu)) {
                    ISOException.throwIt(VERIFICATION_SUCCESS);
                } else {
                    ISOException.throwIt(VERIFICATION_FAIL);
                }
                break;
            case 0x42:
                encryptAndSign(apdu);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            case 0x44:
                decryptAndValidate(apdu);
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            
        }
        
    }
    
    private void decryptAndValidate(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = 0;
        len = apdu.setIncomingAndReceive();
        if (len > 80 || len % 16 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        try {
            aes_cipher.init(enc_key, Cipher.MODE_DECRYPT, aes_iv, (short) 0, (short) 16);
            mac_sig.init(mac_sig_key, Signature.MODE_VERIFY, mac_sig_iv, (short) 0, (short) 16);
            
            boolean verified = mac_sig.verify(buf, ISO7816.OFFSET_CDATA, (short) (len - 16), buf, (short) (ISO7816.OFFSET_CDATA + (short) (len - 16)), (short) 16);
            if (!verified) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            
            aes_cipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short) (len - 16), pole, (short) 0);
            short apdu_out_len = apdu.setOutgoing();
            if (apdu_out_len != (len - 16)) {
                apdu_out_len = (short) (len - 16);
            }
            apdu.setOutgoingLength(apdu_out_len);
            apdu.sendBytesLong(pole, (short) 0, apdu_out_len);
            
        } catch (CryptoException e) {
            ISOException.throwIt((short) (ISO7816.SW_WRONG_LENGTH + e.getReason()));
        }
        
    }
    
    private void encryptAndSign(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = 0;
        len = apdu.setIncomingAndReceive();
        if (len > 64 || len % 16 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        try {
            aes_cipher.init(enc_key, Cipher.MODE_ENCRYPT, aes_iv, (short) 0, (short) 16);
            mac_sig.init(mac_sig_key, Signature.MODE_SIGN, mac_sig_iv, (short) 0, (short) 16);
            aes_cipher.doFinal(buf, ISO7816.OFFSET_CDATA, len, pole, (short) 0);
            short mac_len = mac_sig.sign(pole, (short) 0, len, pole, (short) len);
            short apdu_out_len = apdu.setOutgoing();
            if ((len + mac_len) != apdu_out_len) {
                apdu_out_len = (short) (len + mac_len);
            }
            apdu.setOutgoingLength(apdu_out_len);
            apdu.sendBytesLong(pole, (short) 0, apdu_out_len);
            
        } catch (CryptoException e) {
            ISOException.throwIt((short) (ISO7816.SW_WRONG_LENGTH + e.getReason()));
        }
    }
    
    private void sayMyName(APDU apdu) {
        short len = 0;
        len = apdu.setOutgoing();
        if (len > (short) jmeno.length) {
            len = (short) jmeno.length;
        }
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(jmeno, (short) 0, len);
    }
    
    private short readData(APDU apdu) {
        short len = 0;
        len = apdu.setIncomingAndReceive();
        if (len > 20) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte buf[] = apdu.getBuffer();
        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, pole, (short) 0, len);
        return len;
    }
    
    private void sendData(APDU apdu, short delka_pole) {
        short len = 0;
        len = apdu.setOutgoing();
        if (delka_pole == len) {
            apdu.setOutgoingLength(delka_pole);
            apdu.sendBytesLong(pole, (short) 0, delka_pole);
        } else {
            ISOException.throwIt((short) (0x6c00 + delka_pole));
        }
    }
    
    private boolean verifyPin(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            
        }
        short len = 0;
        len = apdu.setIncomingAndReceive();
        if (len != PIN_LENGTH) {
            return false;
        }
        byte buf[] = apdu.getBuffer();
        return pin.check(buf, ISO7816.OFFSET_CDATA, (byte) len);
    }
    
    private boolean verified() {
        if (pin.isValidated()) {
            return true;
        } else {
            ISOException.throwIt(PIN_VERIFICATION_REQUIRED);
        }
        return false;
    }
}
