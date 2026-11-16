package com.capyvault.app;

import static org.junit.Assert.*;

import org.junit.Test;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class VaultFormatTest {
    @Test public void opensRustWindowsFixture() throws Exception {
        byte[] file;
        try(InputStream in=getClass().getClassLoader().getResourceAsStream("windows-rust-fixture.capyvault")) {
            assertNotNull(in); file=in.readAllBytes();
        }
        byte[] password="Fictional-Only-2026!".getBytes(StandardCharsets.UTF_8);
        VaultFormat.Session session=VaultFormat.unlock(file,password,false);
        byte[] plain=session.decryptPayload();
        String data=new String(plain,StandardCharsets.UTF_8);
        assertTrue(data.contains("\"schema_version\":1"));
        assertTrue(data.contains("\"service\":\"Fictional Mail\""));
        session.destroy(); Arrays.fill(password,(byte)0); Arrays.fill(plain,(byte)0);
    }

    @Test public void createsOpensAndReencryptsV1() throws Exception {
        byte[] password="Dummy-Android-Test-2026!".getBytes(StandardCharsets.UTF_8);
        byte[] plain="{\"schema_version\":1,\"records\":[]}".getBytes(StandardCharsets.UTF_8);
        VaultFormat.Created made=VaultFormat.create(plain,password);
        VaultFormat.Session opened=VaultFormat.unlock(made.bytes,password,false);
        byte[] current=opened.decryptPayload(); assertArrayEquals(plain,current);
        byte[] replacement="{\"schema_version\":1,\"records\":[{\"service\":\"Test\"}]}".getBytes(StandardCharsets.UTF_8);
        byte[] saved=opened.replacePayload(replacement); assertArrayEquals(replacement,opened.openSnapshot(saved));
        VaultFormat.Session recovered=VaultFormat.unlock(saved,VaultFormat.recoveryBytes(made.recoveryKey),true);
        assertArrayEquals(replacement,recovered.decryptPayload());
        made.session.destroy();opened.destroy();recovered.destroy();Arrays.fill(password,(byte)0);Arrays.fill(plain,(byte)0);Arrays.fill(current,(byte)0);Arrays.fill(replacement,(byte)0);
    }
}
