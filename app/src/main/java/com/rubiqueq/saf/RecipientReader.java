// Replacement for app/src/main/java/com/rubiqueq/saf/RecipientReader.java
package com.rubiqueq.saf;

import android.content.Context;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.database.Cursor;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import java.util.*;
import java.util.zip.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public final class RecipientReader {
  public static final class Recipient {
    public final String phone,message,consentSource;
    public final boolean optedIn;
    public Recipient(String phone,String message,boolean optedIn,String consentSource){
      this.phone=phone;this.message=message;this.optedIn=optedIn;this.consentSource=consentSource;
    }
  }
  private static String normalize(String raw){
    if(raw==null)return "";
    String s=raw.trim().replace("\u200c","").replaceAll("[\\s\\-()+]","");
    s=s.replace('۰','0').replace('۱','1').replace('۲','2').replace('۳','3').replace('۴','4').replace('۵','5').replace('۶','6').replace('۷','7').replace('۸','8').replace('۹','9');
    s=s.replace('٠','0').replace('١','1').replace('٢','2').replace('٣','3').replace('٤','4').replace('٥','5').replace('٦','6').replace('٧','7').replace('٨','8').replace('٩','9');
    if(s.contains("E")||s.contains("e")){try{s=new BigDecimal(s).toBigIntegerExact().toString();}catch(Exception ignored){}}
    if(s.endsWith(".0"))s=s.substring(0,s.length()-2);
    if(s.startsWith("0098"))s=s.substring(2);
    if(s.startsWith("98"))s="0"+s.substring(2);
    else if(s.matches("9[0-9]{9}"))s="0"+s;
    return s;
  }
  private static String at(List<String> line,int i){return i<0||i>=line.size()?"":line.get(i).trim();}
  private static int column(List<String> headers,String... aliases){
    for(int i=0;i<headers.size();i++){String h=headers.get(i).trim().toLowerCase(Locale.ROOT);
      for(String alias:aliases)if(h.equals(alias))return i;}
    return -1;
  }
  private static boolean approved(String x){String s=x.toLowerCase(Locale.ROOT).trim();return s.equals("true")||s.equals("yes")||s.equals("1")||s.equals("بله")||s.equals("تایید");}
  public static List<Recipient> read(Context ctx,Uri uri) throws Exception {
    String name="";
    try(Cursor c=ctx.getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
      if(c!=null&&c.moveToFirst())name=c.getString(0);
    }
    try(InputStream in=ctx.getContentResolver().openInputStream(uri)){
      if(in==null)throw new IOException("فایل در دسترس نیست");
      List<List<String>> table=name!=null&&name.toLowerCase(Locale.ROOT).endsWith(".xlsx")?xlsx(in):csv(in);
      if(table.isEmpty())throw new IOException("فایل خالی است");
      List<String> headers=table.get(0);
      int p=column(headers,"phone","mobile","phone_number","number","شماره","شماره موبایل","موبایل","تلفن");
      int m=column(headers,"message","text","متن","پیام");
      int o=column(headers,"opt_in","consent","رضایت","مجاز");
      int source=column(headers,"opt_in_source","consent_source","منبع رضایت");
      if(p<0)throw new IOException("ستون شماره موبایل / phone پیدا نشد");
      LinkedHashMap<String,Recipient> dedup=new LinkedHashMap<>();
      for(int i=1;i<table.size();i++){
        List<String> row=table.get(i);
        String number=normalize(at(row,p));
        if(!number.matches("09[0-9]{9}"))continue;
        if(!dedup.containsKey(number))dedup.put(number,new Recipient(number,at(row,m),approved(at(row,o)),at(row,source)));
        if(dedup.size()>10000)throw new IOException("حداکثر ده‌هزار مخاطب در یک صف مجاز است");
      }
      return new ArrayList<>(dedup.values());
    }
  }
  private static List<List<String>> csv(InputStream in)throws Exception {
    byte[] bytes=limited(in,8<<20);
    String s=new String(bytes,StandardCharsets.UTF_8).replace("\uFEFF","");
    ArrayList<List<String>> result=new ArrayList<>();ArrayList<String> line=new ArrayList<>();StringBuilder field=new StringBuilder();boolean quoted=false;
    for(int i=0;i<s.length();i++){
      char c=s.charAt(i);
      if(c=='"'){if(quoted&&i+1<s.length()&&s.charAt(i+1)=='"'){field.append('"');i++;}else quoted=!quoted;}
      else if(!quoted&&(c==','||c==';'||c=='\t')){line.add(field.toString());field.setLength(0);}
      else if(!quoted&&(c=='\r'||c=='\n')){
        if(c=='\r'&&i+1<s.length()&&s.charAt(i+1)=='\n')i++;
        line.add(field.toString());field.setLength(0);result.add(line);line=new ArrayList<>();
      }else field.append(c);
    }
    if(quoted)throw new IOException("CSV دارای گیومه بسته‌نشده است");
    if(field.length()>0||!line.isEmpty()){line.add(field.toString());result.add(line);}
    return result;
  }
  private static byte[] limited(InputStream in,int max)throws IOException {
    ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[8192];int n;
    while((n=in.read(buf))>=0){out.write(buf,0,n);if(out.size()>max)throw new IOException("حجم فایل بیش از حد مجاز است");}
    return out.toByteArray();
  }
  private static Document xml(byte[] b)throws Exception {
    DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
    // Excel exporters may use x:worksheet/x:row; match by namespace, not prefix.
    f.setNamespaceAware(true);
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    f.setFeature("http://xml.org/sax/features/external-general-entities",false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
    f.setExpandEntityReferences(false);
    return f.newDocumentBuilder().parse(new ByteArrayInputStream(b));
  }
  private static List<List<String>> xlsx(InputStream in)throws Exception {
    byte[] sheet=null,shared=null;
    try(ZipInputStream zip=new ZipInputStream(in)){
      ZipEntry entry;
      while((entry=zip.getNextEntry())!=null){
        if(entry.getName().equals("xl/worksheets/sheet1.xml"))sheet=limited(zip,10<<20);
        else if(entry.getName().equals("xl/sharedStrings.xml"))shared=limited(zip,5<<20);
        zip.closeEntry();
      }
    }
    if(sheet==null)throw new IOException("برگه اول Excel پیدا نشد");
    ArrayList<String> stringTable=new ArrayList<>();
    if(shared!=null){NodeList nodes=xml(shared).getElementsByTagNameNS("*", "si");
      for(int i=0;i<nodes.getLength();i++)stringTable.add(nodes.item(i).getTextContent());}
    ArrayList<List<String>> out=new ArrayList<>();
    NodeList rows=xml(sheet).getElementsByTagNameNS("*", "row");
    for(int n=0;n<rows.getLength();n++){
      NodeList cells=((Element)rows.item(n)).getElementsByTagNameNS("*", "c");TreeMap<Integer,String> current=new TreeMap<>();
      for(int j=0;j<cells.getLength();j++){
        Element c=(Element)cells.item(j);String ref=c.getAttribute("r");int col=0;
        for(int k=0;k<ref.length()&&Character.isLetter(ref.charAt(k));k++)col=col*26+(Character.toUpperCase(ref.charAt(k))-'A'+1);
        if(col<1||col>256)continue;
        String type=c.getAttribute("t");NodeList val=c.getElementsByTagNameNS("*", "v");
        String raw=val.getLength()>0?val.item(0).getTextContent():c.getTextContent();
        if("s".equals(type)){try{raw=stringTable.get(Integer.parseInt(raw));}catch(Exception e){raw="";}}
        current.put(col-1,raw);
      }
      ArrayList<String> row=new ArrayList<>();
      int end=current.isEmpty()?0:current.lastKey();
      for(int k=0;k<=end;k++)row.add(current.getOrDefault(k,""));
      out.add(row);
    }
    return out;
  }
}
