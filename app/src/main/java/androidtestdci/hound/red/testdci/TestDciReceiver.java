package androidtestdci.hound.red.testdci;

import android.app.admin.DeviceAdminReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

public class TestDciReceiver extends DeviceAdminReceiver {
    /**
     * @return A newly instantiated {@link android.content.ComponentName} for this
     * DeviceAdminReceiver.
     */
    public static ComponentName getComponentName(Context context) {
        return new ComponentName(context.getApplicationContext(), TestDciReceiver.class);
    }

    /**
     * Called when choosePrivateKeyAlias is called. If the choosePrivateKeyAlias call passes in
     * null for {@code alias} then this method returns null and the user will choose from a list of
     * aliases in KeyChain. If {@code alias} is not null then this method returns the given alias
     * which forces selection of the keypair with the given alias without user input. If a keypair
     * with the {@code alias} passed in doesn't exist then no keypair is selected, so take care to
     * only pass in an alias that you know exists in the KeyChain.
     */
    @Override
    public String onChoosePrivateKeyAlias(Context context, Intent intent, int uid, Uri uri,
                                          String alias) {
        return alias;
    }
}
