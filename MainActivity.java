package dz.archive.server;

import android.app.Activity;import android.app.AlertDialog;import android.content.Intent;import android.os.Bundle;import android.os.Handler;import android.os.Looper;import android.view.Gravity;import android.content.ClipboardManager;import android.content.ClipData;import android.content.Context;import android.net.Uri;import android.text.InputType;import android.widget.*;import android.graphics.Typeface;import java.io.InputStream;import java.io.OutputStream;import java.security.SecureRandom;

public class MainActivity extends Activity {
 private static final int CREATE_BACKUP=41, PICK_BACKUP=42;
 private TextView status,keyView; private String key;
 @Override public void onCreate(Bundle b){super.onCreate(b);key=getSharedPreferences("archive_server",MODE_PRIVATE).getString("shared_key",null);if(key==null){byte[] bytes=new byte[16];new SecureRandom().nextBytes(bytes);StringBuilder s=new StringBuilder();for(byte x:bytes)s.append(String.format(java.util.Locale.ROOT,"%02x",x));key=s.toString();getSharedPreferences("archive_server",MODE_PRIVATE).edit().putString("shared_key",key).apply();}
  LinearLayout root=new LinearLayout(this);root.setOrientation(1);root.setPadding(26,30,26,24);root.setGravity(Gravity.CENTER_HORIZONTAL);ScrollView scroll=new ScrollView(this);scroll.addView(root);
  TextView title=new TextView(this);title.setText("خادم سجل الأرشيف");title.setTextSize(25);title.setTypeface(null,Typeface.BOLD);title.setGravity(Gravity.CENTER);
  status=new TextView(this);status.setText("الخادم متوقف");status.setTextSize(17);status.setGravity(Gravity.CENTER);status.setPadding(0,22,0,18);
  Button start=new Button(this);start.setText("تشغيل الخادم المحلي");start.setOnClickListener(v->{if(android.os.Build.VERSION.SDK_INT>=26)startForegroundService(new Intent(this,LanServerService.class));else startService(new Intent(this,LanServerService.class));status.setText("جارٍ تشغيل الخادم…\n\n"+LanServerService.localAddresses());new Handler(Looper.getMainLooper()).postDelayed(()->status.setText("الخادم يعمل. اكتب أحد العناوين التالية في متصفح الحاسوب:\n\n"+LanServerService.localAddresses()+"\n\nاختبار: أضف /api/health إلى العنوان."),1000);});
  Button stop=new Button(this);stop.setText("إيقاف الخادم");stop.setOnClickListener(v->{stopService(new Intent(this,LanServerService.class));status.setText("تم طلب إيقاف الخادم. انتظر لحظات قبل النسخ أو الاستعادة.");});
  TextView label=new TextView(this);label.setText("رمز اتصال الموظفين (احتفظ به وشاركه مع الموظفين فقط):");label.setPadding(0,26,0,8);label.setTextSize(15);
  keyView=new TextView(this);keyView.setText(key);keyView.setTextIsSelectable(true);keyView.setTextSize(17);keyView.setGravity(Gravity.CENTER);keyView.setPadding(12,12,12,12);keyView.setBackgroundColor(0xffe8eef0);
  Button copy=new Button(this);copy.setText("نسخ رمز الاتصال");copy.setOnClickListener(v->{ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);cm.setPrimaryClip(ClipData.newPlainText("Archive access key",key));Toast.makeText(this,"تم نسخ رمز الاتصال",Toast.LENGTH_SHORT).show();});
  TextView backupTitle=new TextView(this);backupTitle.setText("النسخ الاحتياطي المشفر لقاعدة البيانات المركزية");backupTitle.setTextSize(18);backupTitle.setTypeface(null,Typeface.BOLD);backupTitle.setPadding(0,28,0,8);
  Button backup=new Button(this);backup.setText("إنشاء نسخة احتياطية مشفرة");backup.setOnClickListener(v->askBackupPassword(false));
  Button restore=new Button(this);restore.setText("استعادة نسخة احتياطية مشفرة");restore.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("تأكيد الاستعادة").setMessage("ستُستبدل قاعدة البيانات الحالية بمحتويات النسخة المختارة. أوقف الخادم أولاً، وتأكد أن النسخة تخص هذا التطبيق. سيُحتفظ بنسخة من قاعدة البيانات الحالية للمساعدة على التراجع.").setNegativeButton("إلغاء",null).setPositiveButton("متابعة",(d,w)->askBackupPassword(true)).show());
  TextView backupNote=new TextView(this);backupNote.setText("تُشفّر النسخة باستخدام AES‑256‑GCM وكلمة مرور تختارها (12 حرفاً على الأقل). احتفظ بكلمة المرور في مكان آمن؛ لا يمكن استعادة النسخة بدونها. أوقف الخادم قبل الاستعادة، وبعدها أعد تشغيله. هذه الميزة تجريبية ويجب اختبارها على نسخة بيانات وهمية أولاً.");backupNote.setTextSize(14);backupNote.setPadding(0,8,0,12);
  TextView note=new TextView(this);note.setText("النسخة 1.3-alpha تجريبية. افتح صفحة الأرشيف من حاسوب الموظف، وسيطلب المتصفح رمز الاتصال أول مرة. لا تشارك الرمز خارج شبكة العمل. أبقِ التطبيق والخادم يعملين أثناء الاستخدام.");note.setTextSize(14);note.setPadding(0,18,0,0);
  root.addView(title);root.addView(status);root.addView(start);root.addView(stop);root.addView(label);root.addView(keyView);root.addView(copy);root.addView(backupTitle);root.addView(backup);root.addView(restore);root.addView(backupNote);root.addView(note);setContentView(scroll);
 }
 private void askBackupPassword(boolean restoring){
  EditText input=new EditText(this);input.setSingleLine(true);input.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);input.setHint("كلمة مرور النسخة (12 حرفاً على الأقل)");
  new AlertDialog.Builder(this).setTitle(restoring?"كلمة مرور النسخة الاحتياطية":"تعيين كلمة مرور النسخة الاحتياطية").setView(input).setNegativeButton("إلغاء",null).setPositiveButton("متابعة",(d,w)->{String p=input.getText().toString();if(p.length()<12){toast("يجب أن تكون كلمة المرور 12 حرفاً على الأقل");return;}if(restoring){pendingPass=p;Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("application/octet-stream");startActivityForResult(i,PICK_BACKUP);}else{pendingPass=p;Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("application/octet-stream");i.putExtra(Intent.EXTRA_TITLE,"archive-backup.arcbackup");startActivityForResult(i,CREATE_BACKUP);}}).show();
 }
 private String pendingPass;
 @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){super.onActivityResult(requestCode,resultCode,data);if(resultCode!=RESULT_OK||data==null||data.getData()==null){pendingPass=null;return;}Uri uri=data.getData();final String pass=pendingPass;pendingPass=null;if(pass==null)return;
  status.setText("جارٍ إيقاف الخادم وتجهيز قاعدة البيانات…");stopService(new Intent(this,LanServerService.class));new Handler(Looper.getMainLooper()).postDelayed(()->new Thread(()->{try{
   ArchiveDb helper=new ArchiveDb(this);
   if(requestCode==CREATE_BACKUP){try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){if(out==null)throw new IllegalStateException("تعذر فتح ملف النسخة للحفظ");ArchiveBackup.exportEncrypted(this,helper,out,pass.toCharArray());}runOnUiThread(()->{status.setText("تم إنشاء النسخة الاحتياطية المشفرة. أعد تشغيل الخادم عند الحاجة.");toast("اكتمل إنشاء النسخة الاحتياطية");});}
   else if(requestCode==PICK_BACKUP){try(InputStream in=getContentResolver().openInputStream(uri)){if(in==null)throw new IllegalStateException("تعذر قراءة ملف النسخة");ArchiveBackup.importEncrypted(this,helper,in,pass.toCharArray());}runOnUiThread(()->{status.setText("تمت الاستعادة. أعد تشغيل الخادم وتحقق من البيانات قبل متابعة العمل.");toast("اكتملت الاستعادة");});}
   else helper.close();
  }catch(Exception e){runOnUiThread(()->{status.setText("تعذر إكمال العملية: "+safeError(e)+"\nلم يتم تأكيد نجاح النسخ أو الاستعادة.");toast("فشلت العملية؛ تحقق من كلمة المرور والملف");});}},"archive-backup-worker").start(),700);
 }
 private String safeError(Exception e){String m=e.getMessage();return m==null?e.getClass().getSimpleName():m;}
 private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
}
