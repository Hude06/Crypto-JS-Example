export function parseMessageUserID(data) {
    let temp = []
    for (let i = 0; i < data.length; i++) {
        let newData = data[i]
        if (newData.User_id === null || newData.User_id === undefined || newData.User_id === "" || newData.User_id === "null"){
        } else {
            temp.push(newData.User_id)
        }
    }
    return temp

}
export async function generateAndExportKeyPair() {
    const { publicKey, privateKey } = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    try {
        const exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
        const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);

        return {
            publicKey: exportedPublicKey,
            privateKey: exportedPrivateKey,
        };
    } catch (error) {
        console.error("Key export failed:", error);
        throw new Error("Failed to export the keys.");
    }
}
export function generateRandomString(length) {
    if (length < 1) return '';

    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let randomString = '';

    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        randomString += characters[randomIndex];
    }

    return randomString;
}
export function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
export function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
export async function importPublicKey(exportedKey) {
    return await window.crypto.subtle.importKey(
        "spki", // Format
        exportedKey, // The exported key data
        {
            name: "RSA-OAEP",
            hash: "SHA-256", // Hash function used
        },
        true, // Whether the key is extractable
        ["encrypt"] // Usages
    );
}
export async function encryptData(publicKeyBase64, tempData) {
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyBase64); // Convert base64 to ArrayBuffer
    const publicKey = await importPublicKey(publicKeyBuffer); // Import the key properly
    const encodedData = new TextEncoder().encode(tempData); // Encode the data
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey, // The public key
        encodedData // Data to encrypt
    );

    return encryptedData; // Return the encrypted data
}
export async function decryptData(privateKeyBase64, encryptedMessage) {
    try {
        const privateKeyBuffer = base64ToArrayBuffer(privateKeyBase64);
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["decrypt"]
        );
        const decryptedMessage = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP",
            },
            privateKey,
            encryptedMessage
        );
        // console.log("Decrypted message buffer:", new TextDecoder().decode(decryptedMessage));
        return new TextDecoder().decode(decryptedMessage);

    } catch (error) {
        throw new Error("Decryption failed: " + error.message);
    }
}
class UserInfo {
    constructor(keys) {
        this.keys = keys
        this.userid = generateRandomString(10)
        this.publickey = null
        this.privatekey = null
    }
    init = async function() {
        console.log("Unit Test Started",true)
        this.keys = await generateAndExportKeyPair();
        this.publickey = this.keys.publicKey
        this.privatekey = this.keys.privateKey
        // await createUser(this.userid, this.publickey,"UnitTest1",supabase2)

    }
}
function Test64() {
    let data = "Hello, world!";
    const encoder = new TextEncoder();
    const arrayBuffer = encoder.encode(data).buffer; 
    let base64 = arrayBufferToBase64(arrayBuffer);
    let newBuffer = base64ToArrayBuffer(base64);
    const decoder = new TextDecoder();
    const decodedData = decoder.decode(newBuffer);
    console.log("Unit Test PASSED BASE64.......", data === decodedData);
}
Test64();
async function testSending() {
    console.log("Unit Test Started",true)
    let user1 = new UserInfo();
    let user2 = new UserInfo();
    await user1.init();
    await user2.init();
    let message = "Hello, world!";
    // SENDING MESSAGE FROM USER 1 TO USER 2
    //Wait for user to fully init
    let encryptedMessage = await encryptData(arrayBufferToBase64(user2.publickey), message);
    // await submitMessage('Messages',arrayBufferToBase64(encryptedMessage),"UNITTEST@test.com",(user1.publickey),user2.userid);
    console.log("Part 1 Passed",true)
    let decryptedMessage = await decryptData(arrayBufferToBase64(user2.privatekey), (encryptedMessage));
    console.log("Got here")
    if (decryptedMessage === message) {
        console.log("Unit Test PASSED.......", true);
    } 
}
testSending();