package com.capyvault.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;

/** Android SAF front end. The user selects each vault; no broad storage permission is requested. */
public final class MainActivity extends Activity {
    private static final int PICK_OPEN = 41, PICK_CREATE = 42;
    private static final int INK=Color.rgb(46,54,49), GREEN=Color.rgb(39,128,101), MINT=Color.rgb(232,243,234), PAPER=Color.rgb(250,248,241), MUTED=Color.rgb(112,122,115);
    private final Handler handler=new Handler(Looper.getMainLooper());
    private Uri vaultUri;
    private VaultFormat.Session session;
    private JSONObject data;
    private byte[] diskHash;
    private long lastTouch=System.currentTimeMillis();
    private LinearLayout body;
    private String query="";

    @Override public void onCreate(Bundle state){super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);getWindow().setStatusBarColor(PAPER);getWindow().setNavigationBarColor(PAPER);getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);showHome();}
    @Override public void onUserInteraction(){super.onUserInteraction();lastTouch=System.currentTimeMillis();}
    @Override protected void onResume(){super.onResume();handler.postDelayed(idleCheck,15000);}
    @Override protected void onStop(){super.onStop();if(session!=null)lockVault();handler.removeCallbacks(idleCheck);}
    private final Runnable idleCheck=new Runnable(){@Override public void run(){if(session!=null&&System.currentTimeMillis()-lastTouch>5*60*1000)lockVault();else handler.postDelayed(this,15000);}};

    private LinearLayout page(){
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(PAPER);root.setPadding(dp(22),dp(16),dp(22),dp(18));
        ScrollView sc=new ScrollView(this);sc.addView(root);setContentView(sc);body=root;
        LinearLayout bar=new LinearLayout(this);bar.setGravity(Gravity.CENTER_VERTICAL);TextView logo=text("🦫",28,INK);bar.addView(logo);TextView brand=text("  CapyVault",23,INK);brand.setTypeface(null,Typeface.BOLD);bar.addView(brand);root.addView(bar,new LinearLayout.LayoutParams(-1,dp(48)));
        return root;
    }
    private void showHome(){page();gap(28);title("Cuentas bajo llave.\nTranquilidad a mano.");gap(8);label("Una bóveda cifrada que viaja contigo, sin cuentas en línea ni sincronización obligatoria.");gap(30);label("EMPIEZA CON TU BÓVEDA");gap(8);button("Abrir bóveda existente",GREEN,()->{Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("*/*");i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(i,PICK_OPEN);});gap(10);button("Crear bóveda nueva",INK,()->{Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("application/octet-stream");i.putExtra(Intent.EXTRA_TITLE,"Main.capyvault");i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);startActivityForResult(i,PICK_CREATE);});gap(24);label("CapyVault solo accede a los archivos que tú eliges. En USB, selecciónalo desde el gestor del sistema.");}
    @Override protected void onActivityResult(int request,int result,Intent intent){super.onActivityResult(request,result,intent);if(result!=RESULT_OK||intent==null||intent.getData()==null)return;Uri picked=intent.getData();try{getContentResolver().takePersistableUriPermission(picked,intent.getFlags()&(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION));}catch(Exception ignored){}vaultUri=picked;if(request==PICK_OPEN)askSecret(false,false);else if(request==PICK_CREATE)askSecret(true,false);}

    private void askSecret(boolean creating,boolean recovery){
        final EditText input=new EditText(this);input.setSingleLine(true);input.setHint(recovery?"Clave de recuperación": "Contraseña maestra");if(!recovery)input.setInputType(129);
        LinearLayout wrap=card();wrap.addView(input,new LinearLayout.LayoutParams(-1,dp(52)));
        new AlertDialog.Builder(this).setTitle(creating?"Crear bóveda":"Desbloquear bóveda").setMessage(recovery?"Pega tu clave de recuperación independiente.":"La contraseña solo se usa para derivar la clave y no se guarda.").setView(wrap).setNegativeButton("Cancelar",(d,w)->showHome()).setNeutralButton(recovery?"Usar contraseña":"Usar recuperación",(d,w)->askSecret(creating,!recovery)).setPositiveButton(creating?"Crear":"Desbloquear",(d,w)->{byte[] secret=input.getText().toString().getBytes(StandardCharsets.UTF_8);try{if(creating)createVault(secret);else openVault(secret,recovery);}catch(Exception e){wipe(secret);showError("No se pudo abrir la bóveda. Comprueba la contraseña, la clave o el archivo.");}}).show();
    }

    private void createVault(byte[] password)throws Exception{
        JSONObject empty=new JSONObject();empty.put("schema_version",1);empty.put("records",new JSONArray());byte[] plain=empty.toString().getBytes(StandardCharsets.UTF_8);
        VaultFormat.Created created=VaultFormat.create(plain,password);writeUri(vaultUri,created.bytes);byte[] verify=readUri(vaultUri);if(!Arrays.equals(created.bytes,verify))throw new Exception("No se verificó el guardado");diskHash=sha(verify);session=created.session;data=empty;wipe(plain);wipe(password);showRecovery(created.recoveryKey);showVault();
    }
    private void openVault(byte[] secret,boolean recovery)throws Exception{
        byte[] file=readUri(vaultUri);session=VaultFormat.unlock(file,secret,recovery);diskHash=sha(file);byte[] plain=session.decryptPayload();data=new JSONObject(new String(plain,StandardCharsets.UTF_8));wipe(plain);wipe(secret);if(data.optInt("schema_version",0)!=1||data.optJSONArray("records")==null)throw new Exception("Formato de datos no compatible");showVault();
    }
    private void showRecovery(String key){TextView msg=text("Esta clave se muestra una sola vez. Guárdala separada del USB. No la copies a la misma bóveda.",16,INK);TextView field=text(key,15,GREEN);field.setTextIsSelectable(true);new AlertDialog.Builder(this).setTitle("Guarda tu clave de recuperación").setView(field).setMessage(msg.getText()).setPositiveButton("Copiar y continuar",(d,w)->{ClipboardManager cm=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);cm.setPrimaryClip(ClipData.newPlainText("Clave de recuperación",key));showVault();}).setNegativeButton("Ya la he guardado",(d,w)->showVault()).setCancelable(false).show();}

    private void showVault(){page();LinearLayout top=new LinearLayout(this);top.setGravity(Gravity.CENTER_VERTICAL);TextView heading=text("Tu bóveda",25,INK);heading.setTypeface(null,Typeface.BOLD);top.addView(heading,new LinearLayout.LayoutParams(0,dp(50),1));Button lock=buttonInline("Bloquear",INK,this::lockVault);top.addView(lock);body.addView(top);TextView path=text(fileName(vaultUri),12,MUTED);body.addView(path);gap(8);EditText search=new EditText(this);search.setSingleLine(true);search.setHint("Buscar cuenta, usuario o etiqueta...");search.setText(query);body.addView(search,new LinearLayout.LayoutParams(-1,dp(48)));gap(8);search.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int st,int c,int a){}public void onTextChanged(CharSequence s,int st,int before,int count){query=s.toString();renderRecords();}public void afterTextChanged(android.text.Editable e){}});button("＋  Nueva cuenta",GREEN,()->newRecord());gap(10);button("Guardar cambios",INK,()->saveVault());gap(12);body.addView(text("CUENTAS",12,MUTED));renderRecords();}
    private void renderRecords(){if(body==null||data==null)return;int n=body.getChildCount();while(n>8){body.removeViewAt(8);n--;}JSONArray records=data.optJSONArray("records");if(records==null)return;String q=query.toLowerCase();for(int i=0;i<records.length();i++){JSONObject r=records.optJSONObject(i);if(r==null)continue;String service=r.optString("service"),user=r.optString("username");String tags=r.optJSONArray("tags")==null?"":r.optJSONArray("tags").toString();if(!q.isEmpty()&&!(service+" "+user+" "+tags).toLowerCase().contains(q))continue;LinearLayout row=card();TextView name=text(service.isEmpty()?"Sin nombre":service,18,INK);name.setTypeface(null,Typeface.BOLD);row.addView(name);row.addView(text(user.isEmpty()?"Sin usuario":user,14,MUTED));LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.topMargin=dp(7);body.addView(row,lp);row.setOnClickListener(v->showRecord(r));}}

    private void newRecord(){LinearLayout form=card();EditText service=field(form,"Servicio");EditText username=field(form,"Nombre de usuario");EditText password=field(form,"Contraseña (opcional)");password.setInputType(129);EditText url=field(form,"URL");EditText notes=field(form,"Notas");new AlertDialog.Builder(this).setTitle("Nueva cuenta").setView(form).setNegativeButton("Cancelar",null).setPositiveButton("Añadir",(d,w)->{try{long now=System.currentTimeMillis()/1000;JSONObject r=new JSONObject();r.put("id",UUID.randomUUID().toString());r.put("service",service.getText().toString());r.put("username",username.getText().toString());r.put("password",password.getText().toString());r.put("url",url.getText().toString());r.put("email","");r.put("category","General");r.put("tags",new JSONArray());r.put("created_at",now);r.put("modified_at",now);r.put("notes",notes.getText().toString());r.put("recovery_methods",new JSONArray());r.put("totp_secret","");r.put("custom_fields",new JSONArray());data.getJSONArray("records").put(r);showVault();}catch(Exception e){showError("No se pudo añadir la cuenta.");}}).show();}
    private void showRecord(JSONObject r){LinearLayout box=card();box.addView(text("USUARIO",12,MUTED));box.addView(text(r.optString("username"),17,INK));gapIn(box,10);box.addView(text("CONTRASEÑA",12,MUTED));TextView secret=text("••••••••••••",17,INK);box.addView(secret);Button reveal=buttonInline("Mostrar",GREEN,()->secret.setText(r.optString("password")));box.addView(reveal);Button copy=buttonInline("Copiar",GREEN,()->copyAndClear(r.optString("password")));box.addView(copy);new AlertDialog.Builder(this).setTitle(r.optString("service")).setView(box).setPositiveButton("Cerrar",null).setNeutralButton("Eliminar",(d,w)->new AlertDialog.Builder(this).setMessage("¿Eliminar esta cuenta de la bóveda?").setNegativeButton("Cancelar",null).setPositiveButton("Eliminar",(x,y)->{JSONArray a=data.optJSONArray("records"),b=new JSONArray();for(int i=0;i<a.length();i++){JSONObject v=a.optJSONObject(i);if(v!=null&&!v.optString("id").equals(r.optString("id")))b.put(v);}try{data.put("records",b);}catch(Exception ignored){}showVault();}).show()).show();}
    private void copyAndClear(String value){ClipboardManager cm=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);cm.setPrimaryClip(ClipData.newPlainText("CapyVault",value));handler.postDelayed(()->{if(cm.hasPrimaryClip()&&cm.getPrimaryClip().getItemCount()>0&&value.contentEquals(cm.getPrimaryClip().getItemAt(0).coerceToText(this)))cm.setPrimaryClip(ClipData.newPlainText("",""));},30000);}
    private void saveVault(){try{byte[] onDisk=readUri(vaultUri);if(!MessageDigest.isEqual(sha(onDisk),diskHash))throw new Exception("La bóveda cambió en otro dispositivo. Vuelve a abrirla antes de guardar.");if(onDisk.length>0){File dir=new File(getFilesDir(),"encrypted-backups");if(!dir.exists()&&!dir.mkdirs())throw new Exception("No se pudo crear la copia de seguridad");File backup=new File(dir,System.currentTimeMillis()+".capyvault");try(FileOutputStream f=new FileOutputStream(backup)){f.write(onDisk);f.getFD().sync();}}byte[] plain=data.toString().getBytes(StandardCharsets.UTF_8);byte[] next=session.replacePayload(plain);writeUri(vaultUri,next);byte[] check=readUri(vaultUri);if(!Arrays.equals(next,check))throw new Exception("La comprobación de escritura no coincide");byte[] verified=session.openSnapshot(check);if(!Arrays.equals(plain,verified))throw new Exception("La autenticación posterior al guardado no coincide");diskHash=sha(check);wipe(plain);wipe(verified);showVault();new AlertDialog.Builder(this).setMessage("Cambios guardados y comprobados.").setPositiveButton("Aceptar",null).show();}catch(Exception e){showError("No se pudo guardar: "+e.getMessage());}}
    private void lockVault(){if(session!=null)session.destroy();session=null;data=null;diskHash=null;query="";vaultUri=null;showHome();}

    private byte[] readUri(Uri uri)throws Exception{try(InputStream in=getContentResolver().openInputStream(uri);ByteArrayOutputStream out=new ByteArrayOutputStream()){if(in==null)throw new Exception("No se pudo leer el archivo");byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1){if(out.size()+n>1024*1024*1024)throw new Exception("Bóveda demasiado grande");out.write(b,0,n);}return out.toByteArray();}}
    private void writeUri(Uri uri,byte[] bytes)throws Exception{try(OutputStream out=getContentResolver().openOutputStream(uri,"rwt")){if(out==null)throw new Exception("El proveedor no permite guardar este archivo");out.write(bytes);out.flush();if(out instanceof FileOutputStream)((FileOutputStream)out).getFD().sync();}}
    private byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    private String fileName(Uri uri){try(android.database.Cursor c=getContentResolver().query(uri,null,null,null,null)){if(c!=null&&c.moveToFirst()){int i=c.getColumnIndex(OpenableColumns.DISPLAY_NAME);if(i>=0)return c.getString(i);}}catch(Exception ignored){}return uri==null?"":uri.getLastPathSegment();}
    private EditText field(LinearLayout host,String hint){EditText e=new EditText(this);e.setSingleLine(false);e.setHint(hint);host.addView(e,new LinearLayout.LayoutParams(-1,dp(52)));return e;}
    private void showError(String s){new AlertDialog.Builder(this).setTitle("CapyVault").setMessage(s).setPositiveButton("Aceptar",null).show();}
    private void wipe(byte[] b){if(b!=null)Arrays.fill(b,(byte)0);}
    private void title(String s){TextView v=text(s,29,INK);v.setTypeface(Typeface.create("sans-serif",Typeface.NORMAL));body.addView(v);}
    private void label(String s){TextView v=text(s,15,MUTED);body.addView(v);}
    private TextView text(String s,int size,int color){TextView v=new TextView(this);v.setText(s);v.setTextSize(size);v.setTextColor(color);v.setGravity(Gravity.CENTER_VERTICAL);return v;}
    private LinearLayout card(){LinearLayout l=new LinearLayout(this);l.setOrientation(LinearLayout.VERTICAL);l.setPadding(dp(15),dp(9),dp(15),dp(9));GradientDrawable d=new GradientDrawable();d.setColor(Color.WHITE);d.setCornerRadius(dp(13));l.setBackground(d);return l;}
    private void button(String s,int color,Runnable action){Button b=buttonInline(s,color,action);LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,dp(50));body.addView(b,p);}
    private Button buttonInline(String s,int color,Runnable action){Button b=new Button(this);b.setText(s);b.setTextColor(Color.WHITE);b.setAllCaps(false);b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(color));b.setOnClickListener(v->action.run());return b;}
    private void gap(int h){View v=new View(this);body.addView(v,new LinearLayout.LayoutParams(1,dp(h)));}
    private void gapIn(LinearLayout l,int h){View v=new View(this);l.addView(v,new LinearLayout.LayoutParams(1,dp(h)));}
    private int dp(int x){return (int)(x*getResources().getDisplayMetrics().density+0.5f);}
}
