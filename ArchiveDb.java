package dz.archive.server;

import android.content.Context;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public final class ArchiveDb extends SQLiteOpenHelper {
    public ArchiveDb(Context c) { super(c, "archive-central.db", null, 5); }
    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','employee')), permissions_json TEXT NOT NULL DEFAULT '{}', active INTEGER NOT NULL DEFAULT 1, must_change_password INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
        db.execSQL("CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL)");
        db.execSQL("CREATE TABLE archive_state (id INTEGER PRIMARY KEY CHECK(id=1), payload_json TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL)");
        db.execSQL("CREATE TABLE loan_requests (id TEXT PRIMARY KEY, source_record_id TEXT NOT NULL, borrower_username TEXT NOT NULL, status TEXT NOT NULL, rejection_reason TEXT, requested_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT, returned_at TEXT)");
        db.execSQL("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL, recipient TEXT)");
        db.execSQL("CREATE INDEX idx_loan_status ON loan_requests(status)");
        db.execSQL("CREATE INDEX idx_audit_recipient ON audit_log(recipient)");
    }
    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if(oldVersion < 3){
            db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','employee')), permissions_json TEXT NOT NULL DEFAULT '{}', active INTEGER NOT NULL DEFAULT 1, must_change_password INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
            try{db.execSQL("ALTER TABLE users ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '{}'");}catch(Exception ignored){}
            try{db.execSQL("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT ''");}catch(Exception ignored){}
            db.execSQL("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL)");
        }
        if(oldVersion < 5){
            try{db.execSQL("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");}catch(Exception ignored){}
        }
    }
    public synchronized String readState() { try(Cursor c=getReadableDatabase().rawQuery("SELECT payload_json FROM archive_state WHERE id=1",null)){return c.moveToFirst()?c.getString(0):null;} }
    public synchronized int revision() { try(Cursor c=getReadableDatabase().rawQuery("SELECT revision FROM archive_state WHERE id=1",null)){return c.moveToFirst()?c.getInt(0):0;} }
    public synchronized int writeState(String payload,int expectedRevision) {
        SQLiteDatabase db=getWritableDatabase();db.beginTransaction();
        try{int current=0;try(Cursor c=db.rawQuery("SELECT revision FROM archive_state WHERE id=1",null)){if(c.moveToFirst())current=c.getInt(0);}if(current!=expectedRevision)return -1;
            ContentValues v=new ContentValues();v.put("payload_json",payload);v.put("revision",current+1);v.put("updated_at",java.time.Instant.now().toString());if(current==0)v.put("id",1);
            if(current==0)db.insertOrThrow("archive_state",null,v);else db.update("archive_state",v,"id=1",null);db.setTransactionSuccessful();return current+1;
        }finally{db.endTransaction();}
    }

    public synchronized org.json.JSONObject mutateLoan(String action, org.json.JSONObject input, String username, String role, String permissions) throws Exception {
        SQLiteDatabase db=getWritableDatabase(); db.beginTransaction();
        try {
            String payload; int revision;
            try(Cursor c=db.rawQuery("SELECT payload_json,revision FROM archive_state WHERE id=1",null)){
                if(!c.moveToFirst()) throw new IllegalStateException("archive_not_initialized");
                payload=c.getString(0); revision=c.getInt(1);
            }
            org.json.JSONObject state=new org.json.JSONObject(payload);
            org.json.JSONArray records=state.optJSONArray("records");
            if(records==null) throw new IllegalStateException("invalid_archive_state");
            org.json.JSONArray audit=state.optJSONArray("auditLog"); if(audit==null){audit=new org.json.JSONArray();state.put("auditLog",audit);}
            long now=System.currentTimeMillis(); String stamp=java.time.Instant.ofEpochMilli(now).toString();
            org.json.JSONObject result=new org.json.JSONObject();
            if("request".equals(action)){
                org.json.JSONObject loan=input.optJSONObject("loan");
                String sourceId=input.optString("sourceRecordId",""); String sourceGroup=input.optString("sourceGroup","");
                if(loan==null||sourceId.isEmpty()||sourceGroup.isEmpty()) throw new IllegalArgumentException("invalid_loan_request");
                if(!"admin".equals(role)){org.json.JSONObject p= new org.json.JSONObject(permissions).optJSONObject(sourceGroup);if(p==null||!p.optBoolean("loan",false))throw new SecurityException("loan_permission_required");}
                org.json.JSONObject source=findRecord(records,sourceId,sourceGroup);
                if(source==null)throw new IllegalArgumentException("source_record_not_found");
                if("معار".equals(source.optString("loanStatus","")))throw new IllegalStateException("file_already_loaned");
                if(source.has("pendingLoanRequestId")||"بانتظار موافقة المدير".equals(source.optString("loanStatus","")))throw new IllegalStateException("loan_request_pending");
                long loanId=now*1000L+new java.security.SecureRandom().nextInt(1000);
                loan.put("id",loanId);loan.put("group","loans");loan.put("sourceRecordId",source.opt("id"));loan.put("sourceGroup",sourceGroup);
                org.json.JSONObject fields=state.optJSONObject("groupFields");if(fields==null){fields=new org.json.JSONObject();state.put("groupFields",fields);}org.json.JSONArray loanFields=fields.optJSONArray("loans");if(loanFields==null){loanFields=new org.json.JSONArray();fields.put("loans",loanFields);}
                org.json.JSONObject sourceSnapshot=new org.json.JSONObject();org.json.JSONArray sourceFields=fields.optJSONArray(sourceGroup);
                if(sourceFields!=null){for(int fi=0;fi<sourceFields.length();fi++){org.json.JSONArray f=sourceFields.optJSONArray(fi);if(f==null||f.length()<2)continue;String sourceKey=f.optString(0,"");if(!sourceKey.matches("[A-Za-z0-9_-]{1,80}"))continue;Object value=source.opt(sourceKey);if(value==null)value="";sourceSnapshot.put(sourceKey,value);String loanKey="source_"+sourceKey;loan.put(loanKey,value);boolean exists=false;for(int fj=0;fj<loanFields.length();fj++){org.json.JSONArray oldField=loanFields.optJSONArray(fj);if(oldField!=null&&loanKey.equals(oldField.optString(0,""))){exists=true;break;}}if(!exists)loanFields.put(new org.json.JSONArray().put(loanKey,f.optString(1,sourceKey)+" (بيانات الملف)"));}}
                loan.put("sourceSnapshot",sourceSnapshot);loan.put("inventory",source.optString("inventory",""));String fileName=source.optString("title",source.optString("employee",source.optString("dealTitle",source.optString("planTitle",source.optString("fileName","ملف بدون عنوان")))));loan.put("fileName",fileName);
                org.json.JSONArray groups=state.optJSONArray("groups");if(groups!=null){for(int gi=0;gi<groups.length();gi++){org.json.JSONArray g=groups.optJSONArray(gi);if(g!=null&&g.length()>1&&sourceGroup.equals(g.optString(0,""))){loan.put("sourceGroupName",g.optString(1,sourceGroup));break;}}}
                loan.put("borrower",username);loan.put("requester",username);loan.put("loanStatus","بانتظار موافقة المدير");loan.put("requestDate",stamp.substring(0,10));loan.put("loanDate","");loan.put("returnDate","");loan.put("notes","طلب إعارة بانتظار اعتماد المدير");
                source.put("pendingLoanRequestId",loanId);source.put("loanStatus","بانتظار موافقة المدير");records.put(loan);
                audit.put(auditItem(now,username,"طلب إعارة جديد","طلب إعارة الملف «"+loan.optString("fileName","ملف")+"». يتطلب موافقة المدير.",null,loanId));
                result.put("loanId",loanId);
            } else {
                String loanId=input.optString("loanId",""); org.json.JSONObject loan=findRecord(records,loanId,"loans");
                if(loan==null)throw new IllegalArgumentException("loan_not_found");
                String status=loan.optString("loanStatus","");
                if("approve".equals(action)||"reject".equals(action)){
                    if(!"admin".equals(role))throw new SecurityException("admin_only");
                    if(!"بانتظار موافقة المدير".equals(status))throw new IllegalStateException("loan_not_pending");
                    org.json.JSONObject source=findRecord(records,loan.optString("sourceRecordId",""),loan.optString("sourceGroup",""));
                    if(source==null)throw new IllegalStateException("source_record_not_found");
                    if("approve".equals(action)){
                        if("معار".equals(source.optString("loanStatus","")))throw new IllegalStateException("file_already_loaned");
                        loan.put("loanStatus","معار");loan.put("loanDate",stamp.substring(0,10));loan.put("notes","تمت الموافقة على طلب الإعارة من المدير");
                        source.put("loanStatus","معار");source.put("currentLoanId",loan.opt("id"));source.put("currentBorrower",loan.optString("borrower",""));source.remove("pendingLoanRequestId");
                        audit.put(auditItem(now,username,"الموافقة على إعارة","تم اعتماد إعارة «"+loan.optString("fileName","ملف")+"» للمستعير «"+loan.optString("borrower","")+"».",null,loan.optLong("id")));
                        audit.put(auditItem(now,username,"نتيجة طلب الإعارة","تمت الموافقة على طلب إعارة الملف «"+loan.optString("fileName","ملف")+"».",loan.optString("borrower",""),loan.optLong("id")));
                    } else {
                        String reason=input.optString("reason","");
                        if(!("الملف خارج الأرشيف".equals(reason)||"لا يمكن إعارة الملف".equals(reason)||"الملف لا يوجد في الأرشيف".equals(reason)))throw new IllegalArgumentException("invalid_rejection_reason");
                        loan.put("loanStatus","مرفوض");loan.put("rejectionReason",reason);loan.put("notes","رفض المدير الطلب: "+reason);
                        if(source.optString("pendingLoanRequestId","").equals(loanId)){source.remove("pendingLoanRequestId");source.put("loanStatus","متاح");}
                        audit.put(auditItem(now,username,"رفض طلب إعارة","تم رفض طلب «"+loan.optString("fileName","ملف")+"». سبب الرفض: "+reason+".",null,loan.optLong("id")));
                        audit.put(auditItem(now,username,"نتيجة طلب الإعارة","تم رفض طلب إعارة الملف «"+loan.optString("fileName","ملف")+"». سبب الرفض: "+reason+".",loan.optString("borrower",""),loan.optLong("id")));
                    }
                } else if("return".equals(action)){
                    if(!"admin".equals(role)){org.json.JSONObject p=new org.json.JSONObject(permissions).optJSONObject("loans");if(p==null||!p.optBoolean("edit",false))throw new SecurityException("return_permission_required");}
                    if(!"معار".equals(status))throw new IllegalStateException("loan_not_active");
                    loan.put("loanStatus","تم الإرجاع");loan.put("returnDate",stamp.substring(0,10));
                    org.json.JSONObject source=findRecord(records,loan.optString("sourceRecordId",""),loan.optString("sourceGroup",""));
                    if(source!=null&&source.optString("currentLoanId","").equals(loanId)){source.put("loanStatus","متاح");source.remove("currentLoanId");source.remove("currentBorrower");}
                    audit.put(auditItem(now,username,"إرجاع ملف",loan.optString("fileName","ملف")+" — المستعير: "+loan.optString("borrower",""),null,loan.optLong("id")));
                } else throw new IllegalArgumentException("unknown_loan_action");
            }
            ContentValues v=new ContentValues();v.put("payload_json",state.toString());v.put("revision",revision+1);v.put("updated_at",stamp);
            db.update("archive_state",v,"id=1",null);db.setTransactionSuccessful();result.put("revision",revision+1);result.put("state",state);return result;
        } finally {db.endTransaction();}
    }
    private org.json.JSONObject findRecord(org.json.JSONArray records,String id,String group){
        for(int i=0;i<records.length();i++){org.json.JSONObject r=records.optJSONObject(i);if(r!=null&&id.equals(r.optString("id",""))&&group.equals(r.optString("group","")))return r;}return null;
    }
    private org.json.JSONObject auditItem(long now,String username,String action,String detail,String recipient,long loanId)throws Exception{
        org.json.JSONObject a=new org.json.JSONObject();a.put("id",now*1000L+new java.security.SecureRandom().nextInt(1000));a.put("at",java.time.Instant.ofEpochMilli(now).toString());a.put("username",username);a.put("action",action);a.put("detail",detail);a.put("read",false);if(recipient!=null){a.put("recipient",recipient);a.put("userRead",false);}a.put("loanRequestId",loanId);return a;
    }

    public synchronized void setPassword(String username,String passwordHash){
        ContentValues v=new ContentValues();v.put("password_hash",passwordHash);
        getWritableDatabase().update("users",v,"username=? COLLATE NOCASE",new String[]{username});
    }
    public synchronized boolean saveEmployee(String username,String passwordHash,String permissions,String now,boolean passwordProvided){
        SQLiteDatabase db=getWritableDatabase();
        try(Cursor c=db.rawQuery("SELECT role FROM users WHERE username=? COLLATE NOCASE",new String[]{username})){
            if(c.moveToFirst()){
                if("admin".equals(c.getString(0)))return false;
                ContentValues v=new ContentValues();v.put("permissions_json",permissions==null?"{}":permissions);v.put("active",1);
                if(passwordProvided)v.put("password_hash",passwordHash);
                db.update("users",v,"username=? COLLATE NOCASE",new String[]{username});
                return true;
            }
        }
        if(!passwordProvided)return false;
        ContentValues v=new ContentValues();v.put("username",username);v.put("password_hash",passwordHash);v.put("role","employee");v.put("permissions_json",permissions==null?"{}":permissions);v.put("active",1);v.put("created_at",now);
        db.insertOrThrow("users",null,v);return true;
    }
    public synchronized boolean disableEmployee(String username){
        SQLiteDatabase db=getWritableDatabase();
        try(Cursor c=db.rawQuery("SELECT role FROM users WHERE username=? COLLATE NOCASE",new String[]{username})){
            if(!c.moveToFirst()||"admin".equals(c.getString(0)))return false;
        }
        db.beginTransaction();try{ContentValues v=new ContentValues();v.put("active",0);db.update("users",v,"username=? COLLATE NOCASE",new String[]{username});db.delete("sessions","username=? COLLATE NOCASE",new String[]{username});db.setTransactionSuccessful();return true;}finally{db.endTransaction();}
    }
    public synchronized void disableAllUsers(){getWritableDatabase().execSQL("UPDATE users SET active=0");}
    /** Sync account role/permissions without replacing a server-managed password hash. */
    public synchronized void upsertUser(String username,String hash,String role,String permissions,String now){
        if(username==null||username.trim().isEmpty())return;
        SQLiteDatabase db=getWritableDatabase();
        ContentValues v=new ContentValues();
        v.put("role","admin".equals(role)?"admin":"employee");
        v.put("permissions_json",permissions==null?"{}":permissions);
        v.put("active",1);
        int changed=db.update("users",v,"username=? COLLATE NOCASE",new String[]{username.trim()});
        if(changed==0){
            if(hash==null||hash.isEmpty())return;
            v.put("username",username.trim());v.put("password_hash",hash);v.put("created_at",now);
            db.insertOrThrow("users",null,v);
        }
    }
    public synchronized void updatePassword(String username,String passwordHash){
        ContentValues v=new ContentValues();v.put("password_hash",passwordHash);v.put("must_change_password",0);
        if(getWritableDatabase().update("users",v,"username=? COLLATE NOCASE",new String[]{username})!=1)throw new IllegalStateException("user_not_found");
    }
    public synchronized void deleteOtherSessions(String username,String keepTokenHash){
        getWritableDatabase().delete("sessions","username=? COLLATE NOCASE AND token_hash<>?",new String[]{username,keepTokenHash});
    }
    /** Admin-initiated password reset for an employee; all existing sessions are revoked atomically. */
    public synchronized boolean resetEmployeePassword(String username,String passwordHash){
        SQLiteDatabase db=getWritableDatabase();db.beginTransaction();
        try{
            int changed;
            try(Cursor c=db.rawQuery("SELECT role,active FROM users WHERE username=? COLLATE NOCASE",new String[]{username})){
                if(!c.moveToFirst()||"admin".equals(c.getString(0)))return false;
            }
            ContentValues values=new ContentValues();values.put("password_hash",passwordHash);values.put("active",1);values.put("must_change_password",1);
            changed=db.update("users",values,"username=? COLLATE NOCASE",new String[]{username});
            if(changed!=1)return false;
            db.delete("sessions","username=? COLLATE NOCASE",new String[]{username});
            db.setTransactionSuccessful();return true;
        }finally{db.endTransaction();}
    }
    public synchronized boolean hasUsers(){try(Cursor c=getReadableDatabase().rawQuery("SELECT COUNT(*) FROM users",null)){return c.moveToFirst()&&c.getInt(0)>0;}}
    public synchronized void createUser(String username,String hash,String role,String permissions,String now){ContentValues v=new ContentValues();v.put("username",username);v.put("password_hash",hash);v.put("role",role);v.put("permissions_json",permissions);v.put("created_at",now);getWritableDatabase().insertOrThrow("users",null,v);}
    public synchronized android.database.Cursor user(String username){return getReadableDatabase().rawQuery("SELECT username,password_hash,role,permissions_json,active,must_change_password FROM users WHERE username=? COLLATE NOCASE",new String[]{username});}
    public synchronized boolean sessionUser(String tokenHash,long now,String[] result){try(Cursor c=getReadableDatabase().rawQuery("SELECT u.username,u.role,u.permissions_json,u.must_change_password FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",new String[]{tokenHash,String.valueOf(now)})){if(!c.moveToFirst())return false;result[0]=c.getString(0);result[1]=c.getString(1);result[2]=c.getString(2);if(result.length>3)result[3]=String.valueOf(c.getInt(3));return true;}}
    public synchronized void saveSession(String tokenHash,String username,long expires,String now){ContentValues v=new ContentValues();v.put("token_hash",tokenHash);v.put("username",username);v.put("expires_at",expires);v.put("created_at",now);getWritableDatabase().insertOrThrow("sessions",null,v);}
    public synchronized void deleteSession(String tokenHash){getWritableDatabase().delete("sessions","token_hash=?",new String[]{tokenHash});}
}
