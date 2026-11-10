package com.rubiqueq.saf;

import android.content.Context;
import android.net.Uri;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public final class RecipientReader {
  public static final class Recipient {
    public final String phone;
    public final String message;
    public final boolean optedIn;
    public Recipient(String p,String m,boolean o){phone=p;message=m;optedIn=o;}
  }
  private static String normalize(String s) {
    if(s==null)return "";
    s=s.trim().replace("\u200c","").replaceAll("[\\s\\-()]", "");
    s=s.replace('۰','0').replace('۱','1').replace('۲','2').replace('۳','3').replace('۴','4').replace('۵','5').replace('۶','6').replace('۷','7').replace('۸','8').replace('۹','9');
    s=s.replace('٠','0').replace('١','1').replace('٢','2').replace('٣','3').replace('٤','4').replace('٥','5').replace('٦','6').replace('٧','7').replace('٨','8').replace('٩','9');
    if(s.startsWith("+98"))s="0"+s.substring(3);
    else if(s.startsWith("98"))s="0"+s.substring(2);
    return s;
  }
  private static boolean yes(String s){if(s==null)return false;s=s.trim().toLowerCase(Locale.ROOT);return s.equals("true")||s.equals("1")||s.equals("yes")||s.equals("بله")||s.equals("تایید");}
  public static List<Recipient> read(Context ctx,Uri uri)throws Exception{
    String name="";
    try(android.database.Cursor c=ctx.getContentResolver().query(uri,new String[]{android.provider.OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())name=c.getString(0);}
    try(InputStream in=ctx.getContentResolver().openInputStream(uri)){
      if(in==null)throw new IOException("File not accessible");
      List<List<String>> rows=name.toLowerCase(Locale.ROOT).endsWith(".xlsx")?xlsx(in):csv(in);
      if(rows.isEmpty())return Collections.emptyList();
      List<String> h=rows.get(0);
      int p=column(h,"phone","mobile","phone_number","شماره","موبایل","تلفن");
      int consent=column(h,"opt_in","consent","رضایت");
      int m=column(h,"message","text","متن","پیام");
      if(p<0)throw new IOException("ستون شماره/phone موجود نیست");
      LinkedHashMap<String,Recipient> all=new LinkedHashMap<>();
      for(int i=1;i<rows.size();i++){
        List<String> row=rows.get(i);
        String phone=normalize(at(row,p));
        if(!phone.matches("09[0-9]{9}"))continue;
        boolean approved=consent>=0 && yes(at(row,consent));
        if(!all.containsKey(phone))all.put(phone,new Recipient(phone,at(row,m),approved));
      }
      return new ArrayList<>(all.values());
    }
  }
  private static String at(List<String> r,int i){return i>=0&&i<r.size()?r.get(i):"";}
  private static int column(List<String> h,String... names){
    for(int i=0;i<h.size();i++){String s=h.get(i).trim().toLowerCase(Locale.ROOT);for(String n:names)if(s.equals(n)||s.contains(n)&&n.length()>=5)return i;}return -1;
  }
  private static List<List<String>> csv(InputStream in)throws Exception{
    String text=new String(in.readAllBytes(),StandardCharsets.UTF_8).replace("\uFEFF","");
    ArrayList<List<String>> rows=new ArrayList<>(); ArrayList<String> row=new ArrayList<>();StringBuilder cell=new StringBuilder();boolean quote=false;
    for(int i=0;i<text.length();i++){
      char c=text.charAt(i);
      if(c=='"'){if(quote&&i+1<text.length()&&text.charAt(i+1)=='"'){cell.append('"');i++;}else quote=!quote;}
      else if(!quote&&(c==','||c==';')){row.add(cell.toString());cell.setLength(0);}
      else if(!quote&&(c=='\n'||c=='\r')){if(c=='\r'&&i+1<text.length()&&text.charAt(i+1)=='\n')i++;row.add(cell.toString());cell.setLength(0);if(!row.isEmpty())rows.add(row);row=new ArrayList<>();}
      else cell.append(c);
    }
    if(cell.length()>0||!row.isEmpty()){row.add(cell.toString());rows.add(row);}
    return rows;
  }
  private static Document doc(byte[] bytes)throws Exception {
    DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
    f.setFeature("http://xml.org/sax/features/external-general-entities",false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
    f.setExpandEntityReferences(false);
    return f.newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
  }
  private static List<List<String>> xlsx(InputStream in)throws Exception{
    byte[] sheet=null, shared=null;
    try(ZipInputStream zin=new ZipInputStream(in)){
      ZipEntry e;while((e=zin.getNextEntry())!=null){
        if(e.getName().equals("xl/worksheets/sheet1.xml"))sheet=zin.readAllBytes();
        if(e.getName().equals("xl/sharedStrings.xml"))shared=zin.readAllBytes();
        zin.closeEntry();
      }
    }
    if(sheet==null)throw new IOException("XLSX sheet1 not found");
    ArrayList<String> strings=new ArrayList<>();
    if(shared!=null){NodeList si=doc(shared).getElementsByTagName("si");for(int i=0;i<si.getLength();i++)strings.add(si.item(i).getTextContent());}
    NodeList rNodes=doc(sheet).getElementsByTagName("row");ArrayList<List<String>> rows=new ArrayList<>();
    for(int i=0;i<rNodes.getLength();i++){
      Element r=(Element)rNodes.item(i);NodeList cells=r.getElementsByTagName("c");TreeMap<Integer,String> values=new TreeMap<>();
      for(int j=0;j<cells.getLength();j++){
        Element c=(Element)cells.item(j);String ref=c.getAttribute("r");int index=0;
        for(int k=0;k<ref.length()&&Character.isLetter(ref.charAt(k));k++)index=index*26+(Character.toUpperCase(ref.charAt(k))-'A'+1);
        if(index<=0||index>256)continue;
        NodeList v=c.getElementsByTagName("v");
        String value=v.getLength()>0?v.item(0).getTextContent():c.getTextContent();
        if("s".equals(c.getAttribute("t"))){try{value=strings.get(Integer.parseInt(value));}catch(Exception ignored){value="";}}
        values.put(index-1,value);
      }
      ArrayList<String> line=new ArrayList<>();
      for(int j=0;j<=Math.min(255,values.isEmpty()?0:values.lastKey());j++)line.add(values.getOrDefault(j,""));
      rows.add(line);
    }
    return rows;
  }
}
