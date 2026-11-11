// Replacement for app/src/main/java/com/rubiqueq/saf/MainActivity.java
// This UI operates a server-persisted schedule; it DOES NOT send 999 messages
// from a fragile Android Thread. A separately authenticated Rubingo backend
// must expose /v1/queue and /v1/media endpoints from queue_adapter.go.
package com.rubiqueq.saf;

import android.app.*;
import android.content.*;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.view.Gravity;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
  private static final int PICK_EXCEL = 171, PICK_IMAGE = 172;
  private final ExecutorService network = Executors.newSingleThreadExecutor();
  private final ArrayList<RecipientReader.Recipient> rows = new ArrayList<>();
  private EditText server, apiKey, phone, password, otp, message, delay;
  private TextView status, summary, selectedTime;
  private Uri imageUri;
  private long startAtMillis = -1;
  private volatile boolean busy = false;

  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
    ScrollView scroll = new ScrollView(this);
    LinearLayout content = new LinearLayout(this);
    content.setOrientation(LinearLayout.VERTICAL);
    content.setPadding(30,24,30,40);
    scroll.addView(content);
    setContentView(scroll);
    TextView title=new TextView(this);
    title.setText("Rubika SAF | صف زمان‌بندی‌شده"); title.setTextSize(21);
    title.setGravity(Gravity.CENTER); content.addView(title);
    server=field(content,"آدرس سرور HTTPS","https://rubika-saf-go-engine-production.up.railway.app",false);
    server.setText(getPreferences(0).getString("server","https://rubika-saf-go-engine-production.up.railway.app"));
    apiKey=field(content,"کلید خصوصی سرور (هر بار وارد کنید)","API Key",true);
    phone=field(content,"شماره حساب شخصی روبیکا","09xxxxxxxxx",false);
    password=field(content,"رمز دو مرحله‌ای، در صورت وجود","2FA",true);
    addButton(content,"۱) دریافت کد ورود",()->requestCode());
    otp=field(content,"کد ورود دریافت‌شده","OTP",false);
    addButton(content,"۲) ورود به حساب روبیکا",()->verifyCode());
    addButton(content,"۳) انتخاب Excel / CSV مخاطبان",()->chooseFile(PICK_EXCEL,"*/*"));
    summary=new TextView(this);summary.setText("هنوز فایلی انتخاب نشده است.");content.addView(summary);
    message=field(content,"متن مشترک (در صورت خالی‌بودن ستون message)","متن پیام",false);
    message.setSingleLine(false);message.setMinLines(2);
    addButton(content,"۴) انتخاب تصویر اختیاری",()->chooseFile(PICK_IMAGE,"image/*"));
    selectedTime=new TextView(this);selectedTime.setText("زمان شروع: تعیین نشده"); content.addView(selectedTime);
    addButton(content,"۵) انتخاب تاریخ و ساعت شروع",()->chooseStart());
    delay=field(content,"فاصله بین ارسال‌ها (ثانیه، حداقل ۳۰)","60",false);delay.setText("60");
    addButton(content,"۶) ثبت و START صف",()->uploadAndStartQueue());
    addButton(content,"STOP / PAUSE",()->queueAction("/v1/queue/pause"));
    addButton(content,"ادامه صف",()->queueAction("/v1/queue/start"));
    addButton(content,"نمایش وضعیت و نتیجه‌ها",()->refreshStatus());
    status=new TextView(this);status.setTextSize(15);status.setPadding(5,20,5,20);content.addView(status);
    status.setText("آماده. اتصال و ارسال واقعی به ورود حساب شخصی و سرور Rubingo نیاز دارد.");
  }
  private EditText field(LinearLayout root,String title,String hint,boolean secret){
    TextView label=new TextView(this);label.setText(title);label.setTextSize(15);label.setPadding(0,12,0,2);root.addView(label);
    EditText e=new EditText(this);e.setHint(hint);e.setSingleLine(true);
    if(secret)e.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
    root.addView(e);return e;
  }
  private void addButton(LinearLayout root,String label,Runnable callback){
    Button b=new Button(this);b.setText(label);root.addView(b);b.setOnClickListener(v->callback.run());
  }
  private String value(EditText e){return e.getText().toString().trim();}
  private void notice(String msg){runOnUiThread(()->status.setText(msg));}
  private void execute(Runnable work){
    if(busy){notice("درخواست قبلی هنوز تمام نشده است.");return;}
    busy=true;network.submit(()->{try{work.run();}finally{busy=false;}});
  }
  private JSONObject call(String path,JSONObject payload) throws Exception {
    String host=value(server).replaceAll("/+$", "");
    if(!host.startsWith("https://"))throw new IOException("سرور باید HTTPS باشد");
    if(value(apiKey).length()<24)throw new IOException("کلید API معتبر وارد نشده است");
    HttpURLConnection c=(HttpURLConnection)new URL(host+path).openConnection();
    try {
      c.setConnectTimeout(20000);c.setReadTimeout(50000);
      c.setRequestProperty("X-API-Key",value(apiKey));
      c.setRequestProperty("Accept","application/json");
      if(payload==null){c.setRequestMethod("GET");}
      else {
        c.setRequestMethod("POST");c.setDoOutput(true);
        c.setRequestProperty("Content-Type","application/json; charset=utf-8");
        try(OutputStream out=c.getOutputStream()){out.write(payload.toString().getBytes(StandardCharsets.UTF_8));}
      }
      int httpStatus=c.getResponseCode();
      InputStream in=httpStatus<400?c.getInputStream():c.getErrorStream();
      String response=in==null?"":new String(in.readAllBytes(),StandardCharsets.UTF_8);
      JSONObject body=response.isEmpty()?new JSONObject():new JSONObject(response);
      if(httpStatus>=400)throw new IOException("HTTP "+httpStatus+" "+body.optString("error","خطای سرور"));
      return body;
    }finally{c.disconnect();}
  }
  private void requestCode(){
    String p=value(phone),secret=value(password);
    if(!p.matches("(\\+98|98|0)?9[0-9]{9}")){notice("شماره معتبر نیست.");return;}
    execute(()->{try{JSONObject r=call("/login/send-code",new JSONObject().put("phone",p).put("password",secret));notice("درخواست کد: "+r.optString("status","unknown"));}catch(Exception e){notice("خطای دریافت کد: "+e.getMessage());}});
  }
  private void verifyCode(){
    String code=value(otp);
    if(!code.matches("[0-9]{4,12}")){notice("کد تأیید معتبر نیست.");return;}
    execute(()->{try{JSONObject r=call("/login/verify",new JSONObject().put("code",code));notice("وضعیت ورود: "+r.optString("status","unknown"));}catch(Exception e){notice("خطای ورود: "+e.getMessage());}});
  }
  private void chooseFile(int request,String mime){
    Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);
    pick.setType(mime);pick.addCategory(Intent.CATEGORY_OPENABLE);
    pick.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
    startActivityForResult(pick,request);
  }
  @Override protected void onActivityResult(int request,int result,Intent data){
    super.onActivityResult(request,result,data);
    if(result!=RESULT_OK||data==null||data.getData()==null)return;
    Uri uri=data.getData();
    try{getContentResolver().takePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(Exception ignored){}
    if(request==PICK_IMAGE){imageUri=uri;notice("تصویر انتخاب شد؛ همراه صف روی سرور آپلود می‌شود.");return;}
    if(request!=PICK_EXCEL)return;
    execute(()->{try{
      List<RecipientReader.Recipient> parsed=RecipientReader.read(this,uri);
      long approved=parsed.stream().filter(r->r.optedIn&&!r.consentSource.isEmpty()).count();
      synchronized(rows){rows.clear();rows.addAll(parsed);}
      runOnUiThread(()->summary.setText("شماره یکتا: "+parsed.size()+" | مجاز با سند رضایت: "+approved));
      notice("فایل خوانده شد. مخاطبان فاقد رضایت ارسال نمی‌شوند.");
    }catch(Exception e){notice("خطای اکسل: "+e.getMessage());}});
  }
  private void chooseStart(){
    Calendar c=Calendar.getInstance();c.add(Calendar.MINUTE,5);
    new DatePickerDialog(this,(picker,year,month,day)->{
      new TimePickerDialog(this,(time,hour,minute)->{
        Calendar chosen=Calendar.getInstance();chosen.set(year,month,day,hour,minute,0);chosen.set(Calendar.MILLISECOND,0);
        startAtMillis=chosen.getTimeInMillis();
        selectedTime.setText("زمان شروع: "+java.text.DateFormat.getDateTimeInstance().format(chosen.getTime()));
      },c.get(Calendar.HOUR_OF_DAY),c.get(Calendar.MINUTE),true).show();
    },c.get(Calendar.YEAR),c.get(Calendar.MONTH),c.get(Calendar.DAY_OF_MONTH)).show();
  }
  private String uploadImage() throws Exception {
    if(imageUri==null)return "";
    byte[] b;
    try(InputStream in=getContentResolver().openInputStream(imageUri)) {
      if(in==null)throw new IOException("تصویر در دسترس نیست");
      ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[32768];int read;
      while((read=in.read(buf))!=-1){out.write(buf,0,read);if(out.size()>5<<20)throw new IOException("تصویر بزرگ‌تر از ۵ مگابایت است");}
      b=out.toByteArray();
    }
    if(b.length==0)throw new IOException("تصویر خالی است");
    JSONObject response=call("/v1/media/upload",new JSONObject().put("base64",Base64.encodeToString(b,Base64.NO_WRAP)));
    String id=response.optString("image_ref", "");
    if(id.isEmpty())throw new IOException("شناسه تصویر دریافت نشد");
    return id;
  }
  private void uploadAndStartQueue(){
    if(startAtMillis<0){notice("تاریخ و ساعت شروع را انتخاب کنید.");return;}
    if(startAtMillis<System.currentTimeMillis()-30000){notice("زمان شروع در گذشته است.");return;}
    final ArrayList<RecipientReader.Recipient> snapshot;
    synchronized(rows){snapshot=new ArrayList<>(rows);}
    if(snapshot.isEmpty()){notice("ابتدا فایل مخاطبان را انتخاب کنید.");return;}
    long approved=snapshot.stream().filter(r->r.optedIn&&!r.consentSource.isBlank()).count();
    if(approved==0){notice("هیچ مخاطبی با رضایت مستند وجود ندارد؛ صف ارسال ایجاد نشد.");return;}
    int seconds;
    try{seconds=Integer.parseInt(value(delay));}catch(Exception e){notice("فاصله نامعتبر است.");return;}
    if(seconds<30||seconds>86400){notice("فاصله باید بین ۳۰ و ۸۶۴۰۰ ثانیه باشد.");return;}
    final int rate=seconds;
    final String fallback=value(message);
    getPreferences(0).edit().putString("server",value(server)).apply();
    execute(()->{try{
      notice("در حال ارسال برنامه زمان‌بندی به سرور...");
      String imageRef=uploadImage();
      JSONArray prepared=new JSONArray();
      for(RecipientReader.Recipient recipient:snapshot){
        String actual=recipient.message.isEmpty()?fallback:recipient.message;
        prepared.put(new JSONObject().put("phone",recipient.phone).put("message",actual)
          .put("opt_in",recipient.optedIn).put("opt_in_source",recipient.consentSource)
          .put("image_ref",imageRef));
      }
      JSONObject plan=new JSONObject().put("start_at",Instant.ofEpochMilli(startAtMillis).toString())
        .put("delay_seconds",rate).put("rows",prepared);
      JSONObject r=call("/v1/queue/plan",plan);
      JSONObject started=call("/v1/queue/start",new JSONObject());
      notice("صف ثبت و فعال شد: "+r.optString("job_id")+" | تعداد "+r.optJSONArray("rows").length()+" | شروع زمان‌بندی‌شده.");
    }catch(Exception e){notice("صف فعال نشد: "+e.getMessage());}});
  }
  private void queueAction(String endpoint){
    execute(()->{try{JSONObject r=call(endpoint,new JSONObject());notice("وضعیت صف: "+r.optString("stop_reason","active")+" | ردیف: "+r.optInt("position",0));}
      catch(Exception e){notice("خطای صف: "+e.getMessage());}});
  }
  private void refreshStatus(){
    execute(()->{try{
      JSONObject r=call("/v1/queue",null);
      JSONArray a=r.optJSONArray("rows");int sent=0,uncertain=0,pending=0,skipped=0;
      if(a!=null)for(int i=0;i<a.length();i++){String state=a.getJSONObject(i).optString("state");
        switch(state){case "submitted":sent++;break;case "uncertain":uncertain++;break;case "pending":pending++;break;case "skipped":skipped++;break;}}
      notice("ارسال ثبت‌شده: "+sent+" | در انتظار: "+pending+" | ردشده: "+skipped+" | نامطمئن: "+uncertain+"\n"+r.optString("stop_reason",""));
    }catch(Exception e){notice("خطای دریافت وضعیت: "+e.getMessage());}});
  }
  @Override protected void onDestroy(){super.onDestroy();network.shutdownNow();}
}
