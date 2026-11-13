package org.androserum.pipeline;
import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.telephony.TelephonyManager;
import android.view.View;

public class MainActivity extends Activity {
    public static volatile String observed;
    public static class Box { public String value; }
    public static String source() { return "controlled-source"; }
    public static String helper(String x) { return x; }
    public static void positiveSink(String x) { observed=x; }
    public static void negativeSink(String x) { observed=x; }
    public static void jointSink(String x) { observed=x; }
    public static void put(Box box,String x) { box.value=x; }
    public static String get(Box box) { return box.value; }
    public static void positive() { positiveSink(helper(source())); }
    public static void negative() { String unused=source();negativeSink("fixed"); }
    public static void earlyReturn(boolean switchOn) { if(!switchOn)return;negativeSink("gate"); }
    public static void bothBranches(boolean flag) { if(flag)negativeSink("yes");else negativeSink("no");negativeSink("joined"); }
    public static void nestedConditions(boolean a,boolean b) { if(a) { if(b)negativeSink("nested"); } }
    public static void guarded(Context context,TelephonyManager manager,boolean switchOn) {
        if(!switchOn)return;
        String id=manager.getDeviceId();Box box=new Box();put(box,id);String payload=get(box);jointSink(payload);
        Intent intent=new Intent(context,TargetActivity.class);intent.putExtra("payload",payload);context.startActivity(intent);
    }
    public void dispatch() { guarded(this,(TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE),true); }
    public static class Clicker implements View.OnClickListener {
        private final MainActivity owner;
        public Clicker(MainActivity owner) { this.owner=owner; }
        public void onClick(View view) { owner.dispatch(); }
    }
    public static class OtherClicker implements View.OnClickListener { public void onClick(View v) { negativeSink("other-listener"); } }
    public static class Work implements Runnable { public void run() { negativeSink("runnable"); } }
    public static class Worker extends Thread { public void run() { negativeSink("thread"); } }
    public static void scheduling(Handler handler) { handler.post(new Work());new Worker().start(); }
    public static void unknownPayload(Context context,String key,String value) {
        Intent intent=new Intent(context,TargetActivity.class);intent.putExtra(key,value);context.startActivity(intent);
    }
    public static void implicit(Context context) {
        Intent intent=new Intent("org.androserum.VIEW");intent.addCategory("android.intent.category.DEFAULT");
        intent.setData(Uri.parse("androserum://test/item"));context.startActivity(intent);
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);positive();negative();earlyReturn(true);bothBranches(true);
        View first=new View(this);first.setOnClickListener(new Clicker(this));
        View second=new View(this);second.setOnClickListener(new OtherClicker());
    }
}
