package com.rubiqueq.saf;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class MainActivity extends Activity {
  private static final int PICK_FILE=501;
  private EditText apiUrl, apiKey, phone, otp, password, text, delay;
  private TextView status;
  private final ArrayList<RecipientReader.Recipient> contacts=new ArrayList<>();
  private volatile boolean running=false;
  private int current=0;
  private LinearLayout layout;
  @Override public void onCreate(Bundle b){
    super.onCreate(b);
    ScrollView scroll=new ScrollView(this);
    layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);layout.setPadding(28,28,28,28);
    scroll.addView(layout);
    setContentView(scroll);
    TextView title=new TextView(this);title.setText("Rubika SAF — نسخه مستقل 1.0.0");title.setTextSize(23);title.setGravity(Gravity.CENTER);layout.addView(title);
    label("آدرس سرور اختصاصی HTTPS"); apiUrl=edit("https://YOUR-SERVER.up.railway.app",false);
    label("کلید دسترسی سرور (از Railway)"); apiKey=edit("API Key",true);
    label("شماره حساب شخصی روبیکا");phone=edit("09xxxxxxxxx",false);
    label("رمز دو مرحله‌ای (در صورت نیاز)");password=edit("2FA اختیاری",true);
    button("۱. ثبت شماره / دریافت کد",()->requestCode());
    label("کد تأیید دریافتی");otp=edit("OTP",false);
    button("۲. تأیید و ورود",()->verifyCode());
    button("۳. انتخاب فایل Excel / CSV",()->{
      Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("*/*");
      i.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,PICK_FILE);
    });
    label("متن پیام (اگر ستون message خالی باشد)");text=edit("متن پیام",false);
    label("فاصله ارسال به ثانیه (حداقل ۳۰)");delay=edit("60",false);delay.setText("60");
    button("START AUTOMATIC — ارسال فقط با رضایت",()->startQueue());
    button("STOP / PAUSE",()->{running=false;show("توقف درخواست شد. صف در دستگاه محفوظ است.");});
    button("بازنشانی صف",()->{if(!running){current=0;persist();show("صف از ابتدا آماده است؛ ارسال مجدد ممکن است تکراری باشد.");}});
    status=new TextView(this);status.setTextSize(16);status.setPadding(0,20,0,20);layout.addView(status);
    load();
    show("آماده. ورود و ارسال واقعی نیازمند سرور Rubingo و تأیید حساب است. "+contacts.size()+" مخاطب، موقعیت "+current);
  }
  private void label(String s){TextView t=new TextView(this);t.setText(s);t.setTextSize(16);t.setPadding(0,14,0,3);layout.addView(t);}
  private EditText edit(String hint,boolean secret){EditText e=new EditText(this);e.setSingleLine(true);e.setHint(hint);if(secret)e.setInputType(129);layout.addView(e);return e;}
  private void button(String s,Runnable callback){
    Button b=new Button(this);b.setText(s);layout.addView(b);b.setOnClickListener(v->callback.run());
  }
  private void show(String s){runOnUiThread(()->status.setText(s));}
  private String val(EditText e){return e.getText().toString().trim();}
  private JSONObject call(String path,JSONObject body)throws Exception{
    String root=val(apiUrl).replaceAll("/+$","");
    if(!root.startsWith("https://"))throw new IOException("آدرس سرور باید HTTPS باشد");
    URL url=new URL(root+path);
    HttpURLConnection c=(HttpURLConnection)url.openConnection();
    try{
      c.setConnectTimeout(20000);c.setReadTimeout(40000);c.setRequestMethod("POST");c.setDoOutput(true);
      c.setRequestProperty("Content-Type","application/json");c.setRequestProperty("X-API-Key",val(apiKey));
      byte[] b=body.toString().getBytes(StandardCharsets.UTF_8);
      try(OutputStream out=c.getOutputStream()){out.write(b);}
      int status=c.getResponseCode();
      InputStream input=status<400?c.getInputStream():c.getErrorStream();
      String raw=input==null?"":new String(input.readAllBytes(),StandardCharsets.UTF_8);
      JSONObject result=raw.isEmpty()?new JSONObject():new JSONObject(raw);
      if(status>=400)throw new IOException("HTTP "+status+": "+result.optString("error",raw));
      return result;
    }finally{c.disconnect();}
  }
  private void requestCode(){
    String p=val(phone),pass=val(password);
    if(!p.matches("(\\+98|98|0)?9[0-9]{9}")){show("شماره تلفن نامعتبر است.");return;}
    show("درخواست ارسال OTP...");
    new Thread(()->{
      try{JSONObject body=new JSONObject().put("phone",p).put("password",pass);JSONObject r=call("/login/send-code",body);show("پاسخ سرور: "+r.optString("status","درخواست ثبت شد"));}
      catch(Exception e){show("خطا دریافت کد: "+e.getMessage());}
    }).start();
  }
  private void verifyCode(){
    show("در حال ورود...");
    new Thread(()->{
      try{JSONObject body=new JSONObject().put("code",val(otp));JSONObject r=call("/login/verify",body);show("ورود: "+r.optString("status","?"));}
      catch(Exception e){show("خطا ورود: "+e.getMessage());}
    }).start();
  }
  @Override protected void onActivityResult(int req,int res,Intent data){
    super.onActivityResult(req,res,data);
    if(req!=PICK_FILE||res!=RESULT_OK||data==null)return;
    Uri uri=data.getData();if(uri==null)return;
    show("در حال خواندن مخاطبان...");
    new Thread(()->{
      try{
        List<RecipientReader.Recipient> rows=RecipientReader.read(this,uri);
        contacts.clear();contacts.addAll(rows);current=0;persist();
        long approved=rows.stream().filter(c->c.optedIn).count();
        show("فایل خوانده شد: "+rows.size()+" شماره یکتا؛ "+approved+" دارای رضایت ثبت‌شده؛ "+(rows.size()-approved)+" غیرمجاز برای ارسال.");
      }catch(Exception e){show("خطای خواندن فایل: "+e.getMessage());}
    }).start();
  }
  private void persist(){
    try{
      JSONArray a=new JSONArray();
      for(RecipientReader.Recipient r:contacts)a.put(new JSONObject().put("p",r.phone).put("m",r.message).put("o",r.optedIn));
      getPreferences(0).edit().putString("queue",a.toString()).putInt("position",current).apply();
    }catch(Exception ignored){}
  }
  private void load(){
    try{
      JSONArray a=new JSONArray(getPreferences(0).getString("queue","[]"));
      for(int i=0;i<a.length();i++){JSONObject j=a.getJSONObject(i);contacts.add(new RecipientReader.Recipient(j.optString("p"),j.optString("m"),j.optBoolean("o",false)));}
      current=Math.max(0,Math.min(contacts.size(),getPreferences(0).getInt("position",0)));
    }catch(Exception ignored){}
  }
  private void startQueue(){
    if(running){show("صف هم‌اکنون در حال اجراست.");return;}
    if(contacts.isEmpty()){show("ابتدا Excel یا CSV وارد کنید.");return;}
    int seconds;
    try{seconds=Math.max(30,Math.min(86400,Integer.parseInt(val(delay))));}catch(Exception e){show("فاصله نامعتبر است");return;}
    String fallback=val(text);
    running=true;
    new Thread(()->{
      try{
        while(running&&current<contacts.size()){
          RecipientReader.Recipient row=contacts.get(current);
          if(!row.optedIn){current++;persist();continue;}
          String message=row.message.isEmpty()?fallback:row.message;
          if(message.isEmpty()){show("پیام خالی است؛ توقف.");break;}
          JSONObject body=new JSONObject().put("phone",row.phone).put("text",message).put("opt_in",true);
          try{
            JSONObject result=call("/send-text",body);
            String id=result.optString("message_id","");
            if(id.isEmpty())throw new IOException("شناسه پیام معتبر برنگشت");
            current++;persist();
            show("ارسال تأییدشده "+current+"/"+contacts.size()+" شناسه "+id);
          }catch(Exception ex){show("صف متوقف شد روی ردیف "+(current+1)+" (برای جلوگیری از تکرار): "+ex.getMessage());break;}
          if(running&&current<contacts.size())Thread.sleep(seconds*1000L);
        }
        if(current>=contacts.size())show("صف تمام شد. "+current+" ردیف بررسی شد.");
      }catch(Exception e){show("صف متوقف شد: "+e.getMessage());}
      finally{running=false;}
    }).start();
  }
}
