package dz.archive.server;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Encrypted full SQLite backup. Format: magic(8), salt(16), nonce(12), AES-GCM ciphertext. */
public final class ArchiveBackup {
    private static final byte[] MAGIC = new byte[]{'A','R','C','B','K','P','0','1'};
    private static final int MAX_DB_BYTES = 100 * 1024 * 1024;
    private ArchiveBackup() {}

    public static void exportEncrypted(Context context, ArchiveDb helper, OutputStream destination, char[] passphrase) throws Exception {
        if (passphrase == null || passphrase.length < 12) throw new IllegalArgumentException("backup_password_too_short");
        SQLiteDatabase db = helper.getWritableDatabase();
        try (Cursor c = db.rawQuery("PRAGMA wal_checkpoint(FULL)", null)) { if (c.moveToFirst() && c.getInt(0) != 0) throw new IllegalStateException("database_checkpoint_busy"); }
        helper.close();
        File source = context.getDatabasePath("archive-central.db");
        byte[] plain = readLimited(new FileInputStream(source), MAX_DB_BYTES);
        byte[] salt = random(16), nonce = random(12);
        byte[] key = derive(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(MAGIC);
        byte[] encrypted = cipher.doFinal(plain);
        destination.write(MAGIC); destination.write(salt); destination.write(nonce); destination.write(encrypted); destination.flush();
        Arrays.fill(plain, (byte)0); Arrays.fill(key, (byte)0); Arrays.fill(passphrase, '\0');
    }

    public static void importEncrypted(Context context, ArchiveDb helper, InputStream input, char[] passphrase) throws Exception {
        if (passphrase == null || passphrase.length < 12) throw new IllegalArgumentException("backup_password_too_short");
        byte[] all = readLimited(input, MAX_DB_BYTES + 128);
        if (all.length < 8 + 16 + 12 + 16 || !Arrays.equals(MAGIC, Arrays.copyOfRange(all, 0, 8))) throw new IllegalArgumentException("invalid_backup_file");
        byte[] salt = Arrays.copyOfRange(all, 8, 24), nonce = Arrays.copyOfRange(all, 24, 36);
        byte[] encrypted = Arrays.copyOfRange(all, 36, all.length), key = derive(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(MAGIC);
        byte[] plain = cipher.doFinal(encrypted); // Wrong password or tampering fails authentication.
        Arrays.fill(key, (byte)0); Arrays.fill(passphrase, '\0');
        if (plain.length < 16 || plain.length > MAX_DB_BYTES) throw new IllegalArgumentException("invalid_database_size");

        File dbFile = context.getDatabasePath("archive-central.db");
        File parent = dbFile.getParentFile(); if (parent == null) throw new IllegalStateException("database_path_unavailable");
        File candidate = new File(parent, "archive-restore-check.db");
        try (FileOutputStream out = new FileOutputStream(candidate)) { out.write(plain); out.getFD().sync(); }
        Arrays.fill(plain, (byte)0);
        validateDatabase(candidate);

        helper.close();
        deleteSidecars(dbFile);
        File old = new File(parent, "archive-central.before-restore.db");
        if (old.exists() && !old.delete()) throw new IllegalStateException("cannot_remove_previous_safety_copy");
        if (dbFile.exists() && !dbFile.renameTo(old)) throw new IllegalStateException("cannot_stage_current_database");
        if (!candidate.renameTo(dbFile)) {
            if (old.exists()) old.renameTo(dbFile);
            throw new IllegalStateException("cannot_install_restored_database");
        }
        deleteSidecars(dbFile);
        // Keep one local pre-restore copy as a rollback aid until the next successful backup.
    }

    private static void validateDatabase(File file) {
        SQLiteDatabase check = SQLiteDatabase.openDatabase(file.getAbsolutePath(), null, SQLiteDatabase.OPEN_READONLY);
        try {
            try (Cursor c = check.rawQuery("PRAGMA integrity_check", null)) {
                if (!c.moveToFirst() || !"ok".equalsIgnoreCase(c.getString(0))) throw new IllegalArgumentException("backup_database_corrupt");
            }
            String[] required = {"users", "sessions", "archive_state", "loan_requests", "audit_log"};
            for (String table : required) {
                try (Cursor c = check.rawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name=?", new String[]{table})) {
                    if (!c.moveToFirst()) throw new IllegalArgumentException("backup_schema_incompatible_" + table);
                }
            }
        } finally { check.close(); }
    }

    private static void deleteSidecars(File db) {
        new File(db.getAbsolutePath() + "-wal").delete();
        new File(db.getAbsolutePath() + "-shm").delete();
        new File(db.getAbsolutePath() + "-journal").delete();
    }
    private static byte[] derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }
    private static byte[] random(int size) { byte[] b = new byte[size]; new SecureRandom().nextBytes(b); return b; }
    private static byte[] readLimited(InputStream input, int max) throws Exception {
        try (InputStream in = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int n;
            while ((n = in.read(buffer)) != -1) { if (out.size() + n > max) throw new IllegalArgumentException("file_too_large"); out.write(buffer, 0, n); }
            return out.toByteArray();
        }
    }
}
