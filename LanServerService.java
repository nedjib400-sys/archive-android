package dz.archive.server;

import android.app.*;
import android.content.Intent;
import android.os.IBinder;
import android.os.Build;
import android.content.pm.ServiceInfo;
import android.content.SharedPreferences;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LanServerService extends Service {
    private volatile boolean running=false; private ServerSocket server; private Thread worker; private final ExecutorService clients=Executors.newFixedThreadPool(8);
    public static final int PORT=8765; private ArchiveDb db;
    @Override public void onCreate(){super.onCreate();db=new ArchiveDb(this);db.getWritableDatabase();}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT>=26)nm.createNotificationChannel(new NotificationChannel("archive_server","خادم الأرشيف",NotificationManager.IMPORTANCE_LOW));
        Notification n=new Notification.Builder(this,"archive_server").setContentTitle("خادم سجل الأرشيف يعمل").setContentText("اترك الخادم يعمل أثناء اتصال الموظفين").setSmallIcon(android.R.drawable.stat_sys_upload_done).build();
        if(Build.VERSION.SDK_INT>=29)startForeground(8765,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);else startForeground(8765,n);
        startServer();return START_STICKY;
    }
    private synchronized void startServer(){if(running)return;running=true;worker=new Thread(()->{try{server=new ServerSocket();server.setReuseAddress(true);server.bind(new InetSocketAddress("0.0.0.0",PORT));while(running){Socket s=server.accept();try{clients.execute(()->handle(s));}catch(java.util.concurrent.RejectedExecutionException busy){try{s.close();}catch(Exception ignored){}}}}catch(Exception e){running=false;}} ,"archive-lan-server");worker.start();}
    private void handle(Socket socket){try(Socket s=socket){s.setSoTimeout(60000);BufferedInputStream in=new BufferedInputStream(s.getInputStream());BufferedOutputStream out=new BufferedOutputStream(s.getOutputStream());
        String req=readLine(in);if(req==null)return;String[] p=req.split(" ");String method=p.length>0?p[0]:"GET";String path=p.length>1?p[1]:"/";Map<String,String> headers=new HashMap<>();String line;while((line=readLine(in))!=null&&!line.isEmpty()){int k=line.indexOf(':');if(k>0)headers.put(line.substring(0,k).trim().toLowerCase(Locale.ROOT),line.substring(k+1).trim());}
        int len=0;try{len=Integer.parseInt(headers.getOrDefault("content-length","0"));}catch(Exception ignored){}if(len>50_000_000){send(out,413,"{\"error\":\"payload_too_large\"}","application/json; charset=utf-8");return;}byte[] raw=readBytes(in,len);String body=new String(raw,StandardCharsets.UTF_8);
        if(path.equals("/api/health")){send(out,200,"{\"ok\":true,\"service\":\"archive-local\",\"api\":\"0.6-alpha\"}","application/json; charset=utf-8");return;}
        if((path.equals("/")||path.equals("/index.html"))&&method.equals("GET")){byte[] html=asset("www/index.html");sendBytes(out,200,html,"text/html; charset=utf-8");return;}
        String key=getSharedKey();if(!constantTimeEquals(key,headers.get("x-archive-key"))){send(out,401,"{\"error\":\"invalid_connection_key\"}","application/json; charset=utf-8");return;}
        if(path.equals("/api/auth/status")&&method.equals("GET")){JSONObject o=new JSONObject();o.put("setupRequired",!db.hasUsers());send(out,200,o.toString(),"application/json; charset=utf-8");return;}
        if(path.equals("/api/auth/setup")&&method.equals("POST")){if(db.hasUsers()){send(out,409,"{\"error\":\"setup_already_done\"}","application/json; charset=utf-8");return;}JSONObject o=new JSONObject(body);String username=o.optString("username","").trim(),password=o.optString("password","");if(username.length()<3||username.length()>40||password.length()<8){send(out,400,"{\"error\":\"invalid_credentials\"}","application/json; charset=utf-8");return;}db.createUser(username,pbkdf2Hash(password),"admin","{}",java.time.Instant.now().toString());issueSession(out,username,"admin","{}",false);return;}
        if(path.equals("/api/auth/login")&&method.equals("POST")){JSONObject o=new JSONObject(body);String username=o.optString("username","").trim(),password=o.optString("password","");try(android.database.Cursor c=db.user(username)){if(!c.moveToFirst()||c.getInt(4)!=1||!passwordMatches(c.getString(1),password)){send(out,401,"{\"error\":\"bad_credentials\"}","application/json; charset=utf-8");return;}String loginName=c.getString(0),storedHash=c.getString(1),loginRole=c.getString(2),loginPermissions=c.getString(3);boolean mustChange=c.getInt(5)==1;if(!storedHash.startsWith("pbkdf2$"))db.updatePassword(loginName,pbkdf2Hash(password));issueSession(out,loginName,loginRole,loginPermissions,mustChange);return;}}
        String token=bearer(headers.get("authorization"));String[] identity=new String[4];boolean authenticated=token!=null&&db.sessionUser(sha256(token),System.currentTimeMillis(),identity);
        if(path.equals("/api/auth/logout")&&method.equals("POST")){if(token!=null)db.deleteSession(sha256(token));send(out,200,"{\"ok\":true}","application/json; charset=utf-8");return;}
        if(path.equals("/api/auth/me")&&method.equals("GET")){if(!authenticated){send(out,401,"{\"error\":\"session_expired\"}","application/json; charset=utf-8");return;}JSONObject o=new JSONObject();o.put("username",identity[0]);o.put("role",identity[1]);o.put("permissions",new JSONObject(identity[2]));o.put("mustChangePassword","1".equals(identity[3]));send(out,200,o.toString(),"application/json; charset=utf-8");return;}
        if(path.equals("/api/auth/password")&&method.equals("POST")){
            if(!authenticated){send(out,401,"{\"error\":\"session_expired\"}","application/json; charset=utf-8");return;}
            JSONObject input=new JSONObject(body);String current=input.optString("currentPassword",""),next=input.optString("newPassword","");
            if(next.length()<8||next.length()>128){send(out,400,"{\"error\":\"password_length\"}","application/json; charset=utf-8");return;}
            try(android.database.Cursor c=db.user(identity[0])){
                if(!c.moveToFirst()||!passwordMatches(c.getString(1),current)){send(out,403,"{\"error\":\"current_password_invalid\"}","application/json; charset=utf-8");return;}
            }
            String tokenHash=sha256(token);db.updatePassword(identity[0],pbkdf2Hash(next));db.deleteOtherSessions(identity[0],tokenHash);
            send(out,200,"{\"ok\":true,\"message\":\"password_changed\"}","application/json; charset=utf-8");return;
        }
        if(path.startsWith("/api/")&&!authenticated){send(out,401,"{\"error\":\"session_required\"}","application/json; charset=utf-8");return;}
        if(authenticated&&"1".equals(identity[3])&&!path.equals("/api/auth/password")&&!path.equals("/api/auth/me")&&!path.equals("/api/auth/logout")){send(out,403,"{\"error\":\"must_change_password\"}","application/json; charset=utf-8");return;}
        if(path.equals("/api/admin/reset-password")&&method.equals("POST")){
            if(!authenticated){send(out,401,"{\"error\":\"session_required\"}","application/json; charset=utf-8");return;}
            if(!"admin".equals(identity[1])){send(out,403,"{\"error\":\"admin_only\"}","application/json; charset=utf-8");return;}
            JSONObject input=new JSONObject(body);String target=input.optString("username","").trim(),next=input.optString("newPassword","");
            if(target.length()<3||target.length()>40||next.length()<8||next.length()>128){send(out,400,"{\"error\":\"invalid_reset_request\"}","application/json; charset=utf-8");return;}
            if(!db.resetEmployeePassword(target,pbkdf2Hash(next))){send(out,404,"{\"error\":\"employee_not_found_or_admin\"}","application/json; charset=utf-8");return;}
            send(out,200,"{\"ok\":true,\"message\":\"password_reset_sessions_revoked\"}","application/json; charset=utf-8");return;
        }
        if(path.startsWith("/api/loans/")&&method.equals("POST")){
            String action=path.substring("/api/loans/".length());
            try{
                JSONObject input=new JSONObject(body);
                JSONObject changed=db.mutateLoan(action,input,identity[0],identity[1],identity[2]);
                if(changed.has("state")&&"admin".equals(identity[1])==false)changed.put("state",filterStateForUser(changed.getJSONObject("state"),identity[2],identity[0]));
                send(out,200,changed.toString(),"application/json; charset=utf-8");return;
            }catch(SecurityException ex){send(out,403,new JSONObject().put("error",ex.getMessage()).toString(),"application/json; charset=utf-8");return;}
             catch(IllegalArgumentException ex){send(out,400,new JSONObject().put("error",ex.getMessage()).toString(),"application/json; charset=utf-8");return;}
             catch(IllegalStateException ex){send(out,409,new JSONObject().put("error",ex.getMessage()).toString(),"application/json; charset=utf-8");return;}
        }
        if(path.equals("/api/revision")&&method.equals("GET")){JSONObject o=new JSONObject();o.put("revision",db.revision());send(out,200,o.toString(),"application/json; charset=utf-8");return;}
        if(path.equals("/api/state")&&method.equals("GET")){String payload=db.readState();JSONObject o=new JSONObject();o.put("revision",db.revision());if(payload==null)o.put("state",JSONObject.NULL);else{JSONObject state=new JSONObject(payload);if(!"admin".equals(identity[1]))state=filterStateForUser(state,identity[2],identity[0]);o.put("state",state);}send(out,200,o.toString(),"application/json; charset=utf-8");return;}
        if(path.equals("/api/state")&&method.equals("PUT")){JSONObject o=new JSONObject(body);int expected=o.optInt("expectedRevision",-1);JSONObject state=o.optJSONObject("state");if(expected<0||state==null){send(out,400,"{\"error\":\"invalid_payload\"}","application/json; charset=utf-8");return;}if(!"admin".equals(identity[1])){String old=db.readState();if(old!=null){JSONObject before=new JSONObject(old);mergeHiddenRecords(before,state,identity[2]);/* الموظف لا يرسل حسابات بقية المستخدمين أصلاً؛ احتفظ بالنسخة الخادمية الكاملة. */state.put("users",before.optJSONArray("users")==null?new org.json.JSONArray():before.optJSONArray("users"));String denial=validateEmployeeStateChange(before,state,identity[2]);if(denial!=null){send(out,403,new JSONObject().put("error",denial).toString(),"application/json; charset=utf-8");return;}/* سجل التدقيق الخادمي لا يقبل التعديل من المتصفح */state.put("auditLog",before.optJSONArray("auditLog")==null?new org.json.JSONArray():before.optJSONArray("auditLog"));}}else{org.json.JSONArray accounts=state.optJSONArray("users");if(accounts!=null){if(accounts.length()>6){send(out,400,"{\"error\":\"maximum_six_accounts\"}","application/json; charset=utf-8");return;}int admins=0;java.util.HashSet<String> names=new java.util.HashSet<>();for(int ai=0;ai<accounts.length();ai++){JSONObject u=accounts.optJSONObject(ai);if(u==null){send(out,400,"{\"error\":\"invalid_account\"}","application/json; charset=utf-8");return;}String un=u.optString("username","").trim().toLowerCase(Locale.ROOT);String accountRole=u.optString("role","");if(un.length()<3||un.length()>40||!names.add(un)||!("admin".equals(accountRole)||"employee".equals(accountRole))||u.optString("hash","").isEmpty()){send(out,400,"{\"error\":\"invalid_or_duplicate_account\"}","application/json; charset=utf-8");return;}if("admin".equals(accountRole))admins++;}if(admins!=1){send(out,400,"{\"error\":\"exactly_one_admin_required\"}","application/json; charset=utf-8");return;}}}
            String recordError=validateUniqueRecordKeys(state);if(recordError!=null){send(out,400,new JSONObject().put("error",recordError).toString(),"application/json; charset=utf-8");return;}
            int next=db.writeState(state.toString(),expected);if(next<0){JSONObject conflict=new JSONObject();conflict.put("error","revision_conflict");conflict.put("revision",db.revision());send(out,409,conflict.toString(),"application/json; charset=utf-8");return;}if("admin".equals(identity[1])){org.json.JSONArray accountList=state.optJSONArray("users");if(accountList!=null){db.disableAllUsers();for(int i=0;i<accountList.length();i++){JSONObject u=accountList.optJSONObject(i);if(u==null)continue;String un=u.optString("username","").trim(),hash=u.optString("hash","");if(un.length()>=3&&!hash.isEmpty())db.upsertUser(un,hash,u.optString("role","employee"),u.optJSONObject("permissions")==null?"{}":u.optJSONObject("permissions").toString(),java.time.Instant.now().toString());}}}JSONObject result=new JSONObject();result.put("ok",true);result.put("revision",next);send(out,200,result.toString(),"application/json; charset=utf-8");return;}
        send(out,404,"{\"error\":\"not_found\"}","application/json; charset=utf-8");
    }catch(Exception ignored){}}
    private void issueSession(BufferedOutputStream out,String username,String role,String permissions,boolean mustChange)throws Exception{byte[] b=new byte[32];new java.security.SecureRandom().nextBytes(b);String token=java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);String hash=sha256(token);String now=java.time.Instant.now().toString();db.saveSession(hash,username,System.currentTimeMillis()+12L*60*60*1000,now);JSONObject o=new JSONObject();o.put("token",token);o.put("expiresIn",43200);o.put("username",username);o.put("role",role);o.put("permissions",new JSONObject(permissions));o.put("mustChangePassword",mustChange);send(out,200,o.toString(),"application/json; charset=utf-8");}
    private String bearer(String h){if(h==null||!h.startsWith("Bearer "))return null;return h.substring(7).trim();}
    private String pbkdf2Hash(String password)throws Exception{
        byte[] salt=new byte[16];new java.security.SecureRandom().nextBytes(salt);int iterations=210000;
        javax.crypto.spec.PBEKeySpec spec=new javax.crypto.spec.PBEKeySpec(password.toCharArray(),salt,iterations,256);
        byte[] derived=javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();spec.clearPassword();
        return "pbkdf2$"+iterations+"$"+java.util.Base64.getEncoder().withoutPadding().encodeToString(salt)+"$"+java.util.Base64.getEncoder().withoutPadding().encodeToString(derived);
    }
    private boolean passwordMatches(String stored,String password)throws Exception{
        if(stored==null||password==null)return false;
        if(stored.startsWith("pbkdf2$")){
            String[] parts=stored.split("\\$",-1);if(parts.length!=4)return false;
            int iterations=Integer.parseInt(parts[1]);if(iterations<100000||iterations>1000000)return false;
            byte[] salt=java.util.Base64.getDecoder().decode(parts[2]),expected=java.util.Base64.getDecoder().decode(parts[3]);
            javax.crypto.spec.PBEKeySpec spec=new javax.crypto.spec.PBEKeySpec(password.toCharArray(),salt,iterations,expected.length*8);
            byte[] actual=javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();spec.clearPassword();
            return java.security.MessageDigest.isEqual(expected,actual);
        }
        return constantTimeEquals(stored,sha256(password))||constantTimeEquals(stored,legacyFallbackHash(password));
    }
    private String legacyFallbackHash(String value){int h=0x811c9dc5;for(byte b:value.getBytes(StandardCharsets.UTF_8))h=(h^(b&255))*16777619;return "fallback-"+Integer.toHexString(h);}
    private String sha256(String value)throws Exception{byte[] d=java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder s=new StringBuilder();for(byte x:d)s.append(String.format(Locale.ROOT,"%02x",x));return s.toString();}
    /** Employees receive only records from groups they may view. */
    private JSONObject filterStateForUser(JSONObject full,String permissionsJson,String username)throws Exception{
        JSONObject permissions=new JSONObject(permissionsJson==null?"{}":permissionsJson);
        org.json.JSONArray records=full.optJSONArray("records"),visible=new org.json.JSONArray();
        if(records!=null)for(int i=0;i<records.length();i++){JSONObject row=records.optJSONObject(i);if(row==null)continue;JSONObject gp=permissions.optJSONObject(row.optString("group",""));if(gp!=null&&gp.optBoolean("view",false))visible.put(row);}
        full.put("records",visible);
        org.json.JSONArray audit=full.optJSONArray("auditLog"),mine=new org.json.JSONArray();
        if(audit!=null)for(int i=0;i<audit.length();i++){JSONObject item=audit.optJSONObject(i);if(item!=null&&username.equalsIgnoreCase(item.optString("recipient","")))mine.put(item);}
        full.put("auditLog",mine);
        org.json.JSONArray users=full.optJSONArray("users"),self=new org.json.JSONArray();
        if(users!=null)for(int i=0;i<users.length();i++){JSONObject user=users.optJSONObject(i);if(user!=null&&username.equalsIgnoreCase(user.optString("username","")))self.put(user);}
        full.put("users",self);return full;
    }
    /** A filtered employee snapshot must not be interpreted as deletion of unseen records. */
    private void mergeHiddenRecords(JSONObject before,JSONObject submitted,String permissionsJson)throws Exception{
        JSONObject permissions=new JSONObject(permissionsJson==null?"{}":permissionsJson);
        org.json.JSONArray oldRows=before.optJSONArray("records"),newRows=submitted.optJSONArray("records");
        if(oldRows==null||newRows==null)return;
        java.util.HashSet<String> submittedKeys=new java.util.HashSet<>();
        for(int i=0;i<newRows.length();i++){JSONObject r=newRows.optJSONObject(i);if(r!=null)submittedKeys.add(r.optString("group","")+"::"+r.optString("id",""));}
        for(int i=0;i<oldRows.length();i++){JSONObject r=oldRows.optJSONObject(i);if(r==null)continue;JSONObject gp=permissions.optJSONObject(r.optString("group",""));if(gp==null||!gp.optBoolean("view",false)){String key=r.optString("group","")+"::"+r.optString("id","");if(!submittedKeys.contains(key))newRows.put(r);}}
    }
    /** Enforce employee permissions at the trusted server boundary, not only in browser UI. */
    private String validateEmployeeStateChange(JSONObject before,JSONObject after,String permissionsJson){
        try{
            if(!sameJson(before.opt("users"),after.opt("users")))return "admin_only_users";
            if(!sameJson(before.opt("groups"),after.opt("groups")))return "admin_only_groups";
            if(!sameJson(before.opt("groupFields"),after.opt("groupFields")))return "admin_only_fields";
            org.json.JSONArray oldRows=before.optJSONArray("records"),newRows=after.optJSONArray("records");
            if(oldRows==null||newRows==null)return "invalid_records";
            if(!sameLoanProtectedData(oldRows,newRows))return "admin_or_loan_api_required";
            JSONObject permissions=new JSONObject(permissionsJson==null?"{}":permissionsJson);
            java.util.Map<String,JSONObject> oldMap=indexRecords(oldRows),newMap=indexRecords(newRows);
            for(java.util.Map.Entry<String,JSONObject> entry:oldMap.entrySet()){
                JSONObject oldRow=entry.getValue(),newRow=newMap.get(entry.getKey());
                String group=oldRow.optString("group","");
                if("loans".equals(group))continue;
                JSONObject gp=permissions.optJSONObject(group);
                if(newRow==null){if(gp==null||!gp.optBoolean("delete",false))return "delete_permission_required";continue;}
                if(!oldRow.similar(newRow)){
                    if(gp==null||!gp.optBoolean("edit",false))return "edit_permission_required";
                    java.util.HashSet<String> keys=new java.util.HashSet<>();java.util.Iterator<String> oi=oldRow.keys();while(oi.hasNext())keys.add(oi.next());java.util.Iterator<String> ni=newRow.keys();while(ni.hasNext())keys.add(ni.next());
                    JSONObject fieldPerms=gp.optJSONObject("fields");
                    for(String key:keys){if("id".equals(key)||"group".equals(key))continue;if(!sameJson(oldRow.opt(key),newRow.opt(key))&&(fieldPerms==null||!fieldPerms.optBoolean(key,false)))return "field_permission_required";}
                }
            }
            for(java.util.Map.Entry<String,JSONObject> entry:newMap.entrySet()){
                if(oldMap.containsKey(entry.getKey()))continue;
                String group=entry.getValue().optString("group","");JSONObject gp=permissions.optJSONObject(group);
                if(gp==null||(!gp.optBoolean("add",false)&&!gp.optBoolean("import",false)))return "add_permission_required";
                JSONObject fieldPerms=gp.optJSONObject("fields");JSONObject added=entry.getValue();java.util.Iterator<String> addedKeys=added.keys();while(addedKeys.hasNext()){String key=addedKeys.next();if("id".equals(key)||"group".equals(key))continue;if(fieldPerms==null||!fieldPerms.optBoolean(key,false))return "field_permission_required";}
            }
            return null;
        }catch(Exception e){return "invalid_permission_payload";}
    }
    /** Reject duplicate or unaddressable records before accepting a whole-state snapshot. */
    private String validateUniqueRecordKeys(JSONObject state){
        org.json.JSONArray rows=state.optJSONArray("records");
        if(rows==null)return "invalid_records";
        java.util.HashSet<String> keys=new java.util.HashSet<>();
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.optJSONObject(i);if(row==null)return "invalid_records";
            String group=row.optString("group","").trim(),id=row.optString("id","").trim();
            if(group.isEmpty()||id.isEmpty())return "invalid_record_key";
            if(!keys.add(group.length()+":"+group+id))return "duplicate_record_key";
        }
        return null;
    }
    private java.util.Map<String,JSONObject> indexRecords(org.json.JSONArray rows){
        java.util.Map<String,JSONObject> out=new java.util.HashMap<>();
        for(int i=0;i<rows.length();i++){JSONObject r=rows.optJSONObject(i);if(r==null)continue;String key=r.optString("group","")+"::"+r.optString("id","");out.put(key,r);}
        return out;
    }
    private boolean sameLoanProtectedData(org.json.JSONArray before,org.json.JSONArray after){
        if(before==null||after==null)return before==after;
        java.util.Map<String,String> protectedRows=new java.util.HashMap<>();
        for(int i=0;i<before.length();i++){org.json.JSONObject r=before.optJSONObject(i);if(r==null)continue;String group=r.optString("group","");if("loans".equals(group)){protectedRows.put("loan:"+r.optString("id",""),r.toString());}else{org.json.JSONObject p=new org.json.JSONObject();for(String k:new String[]{"loanStatus","pendingLoanRequestId","currentLoanId","currentBorrower"})if(r.has(k))p.put(k,r.opt(k));if(p.length()>0)protectedRows.put("source:"+group+":"+r.optString("id",""),p.toString());}}
        java.util.Map<String,String> afterRows=new java.util.HashMap<>();
        for(int i=0;i<after.length();i++){org.json.JSONObject r=after.optJSONObject(i);if(r==null)continue;String group=r.optString("group","");if("loans".equals(group)){afterRows.put("loan:"+r.optString("id",""),r.toString());}else{org.json.JSONObject p=new org.json.JSONObject();for(String k:new String[]{"loanStatus","pendingLoanRequestId","currentLoanId","currentBorrower"})if(r.has(k))p.put(k,r.opt(k));if(p.length()>0)afterRows.put("source:"+group+":"+r.optString("id",""),p.toString());}}
        return protectedRows.equals(afterRows);
    }
    private boolean sameJson(Object a,Object b){return a==null?b==null:a.toString().equals(b==null?null:b.toString());}
    private String getSharedKey(){return getSharedPreferences("archive_server",MODE_PRIVATE).getString("shared_key","");}
    private boolean constantTimeEquals(String a,String b){if(a==null||b==null)return false;return java.security.MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),b.getBytes(StandardCharsets.UTF_8));}
    private byte[] readBytes(InputStream in,int n)throws IOException{byte[] b=new byte[n];int off=0;while(off<n){int r=in.read(b,off,n-off);if(r<0)throw new EOFException();off+=r;}return b;}
    private String readLine(InputStream in)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();int c;while((c=in.read())!=-1){if(c=='\n')break;if(c!='\r')b.write(c);if(b.size()>8192)throw new IOException("header too long");}if(c==-1&&b.size()==0)return null;return b.toString("UTF-8");}
    private byte[] asset(String name)throws IOException{try(InputStream x=getAssets().open(name);ByteArrayOutputStream b=new ByteArrayOutputStream()){byte[] buf=new byte[8192];int n;while((n=x.read(buf))>0)b.write(buf,0,n);return b.toByteArray();}}
    private void send(BufferedOutputStream out,int status,String body,String type)throws IOException{sendBytes(out,status,body.getBytes(StandardCharsets.UTF_8),type);}
    private void sendBytes(BufferedOutputStream out,int status,byte[] body,String type)throws IOException{String label=status==200?"OK":status==401?"Unauthorized":status==403?"Forbidden":status==404?"Not Found":status==409?"Conflict":status==413?"Payload Too Large":status==400?"Bad Request":"Internal Server Error";String h="HTTP/1.1 "+status+" "+label+"\r\nContent-Type: "+type+"\r\nContent-Length: "+body.length+"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";out.write(h.getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();}
    public static String localAddresses(){StringBuilder b=new StringBuilder();try{Enumeration<NetworkInterface> es=NetworkInterface.getNetworkInterfaces();while(es.hasMoreElements()){NetworkInterface ni=es.nextElement();if(!ni.isUp()||ni.isLoopback())continue;Enumeration<InetAddress> as=ni.getInetAddresses();while(as.hasMoreElements()){InetAddress a=as.nextElement();if(a instanceof Inet4Address&&!a.isLoopbackAddress()){if(b.length()>0)b.append("\n");b.append("http://").append(a.getHostAddress()).append(":").append(PORT);}}}}catch(Exception ignored){}return b.length()==0?"لم يتم العثور على عنوان شبكة. تأكد من تشغيل Wi-Fi أو نقطة الاتصال.":b.toString();}
    @Override public void onDestroy(){running=false;try{if(server!=null)server.close();}catch(Exception ignored){}clients.shutdownNow();stopForeground(true);super.onDestroy();}
    @Override public IBinder onBind(Intent i){return null;}
}
