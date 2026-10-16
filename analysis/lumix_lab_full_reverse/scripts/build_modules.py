"""Verified entry declarations and explicit call-site associations; no invented reachability."""
import collections
import re
import zipfile
from common import *
GROUPS={
 'launch_permissions_settings':('AppLaunchScreenActivity','DeepLinkRouterActivity','StartActivity','PermissionConfirmationActivity','PrivacyTermsActivity','SettingActivity','DeviceInfoActivity'),
 'camera_pairing_connection':('CameraFragment','CameraAddFragment','CameraBluetoothConnectionFragment','CameraWifiConnectFragment','CameraUsbConnectionFragment','CameraPairingFragment','LLCBleCentral'),
 'remote_control':('RemoteShootingActivity','RemotePhotostyleActivity','ShutterRemoteControlFragment'),
 'gallery_transfer':('CameraGalleryActivity','GalleryContainerFragment','AutoTransferFilesPreviewActivity','AutoTransferFilesGalleryActivity','ImageTransferSettingsActivity','BurstActivity'),
 'image_lut_edit':('EditActivity','LutFragment','ImageCropActivity'),
 'templates':('TemplateAddFrameActivity','TemplateSelectActivity','Template1SelectColorActivity'),
 'community':('CommunityImageActivity','CommunityDownloadFragment','CommunityCreatorMainFragment'),
 'live_delivery':('LiveDeliveryFragment','LiveDeliverySettingFragment','LiveDeliveryWaitingFragment','LiveDeliveryDeliveringFragment','LiveDeliveryListFragment'),
 'firmware':('FirmwareDetailActivity','FirmwareUpdateListFragment','FirmwareUpdateDetailFragment'),
 'background_notification':('LlcService','ForegroundService','LocationForegroundService','LlcMessagingService','PushNotificationActivity','PushNotificationDetailActivity'),
}
def main():
    classes=jsonl(WORK/'dex_classes.jsonl');methods=jsonl(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
    native={r['method'] for r in methods if r['native']};modules=[];aliases=[]
    for label,names in GROUPS.items():
        roots=[c['class'] for c in classes if c['class'].rsplit('/',1)[-1].removesuffix(';') in names]
        selected=[r for r in methods if r['method'].split('->')[0] in roots]
        associations=[]
        for r in selected:
            for call in r['calls']:
                t=call['reference'];kind=None
                if t in native:kind='app_native_declaration'
                elif any(s in t for s in ('BluetoothGatt','WifiManager;','WifiNetworkSpecifier','ConnectivityManager;','Lh6/a;')):kind='communication_reference'
                elif any(s in t for s in ('Ljava/io/','Landroid/database/','Lcom/panasonic/jp/lumixlab/database/','SharedPreferences;')):kind='storage_reference'
                if kind:associations.append({'caller':r['method'],'dex':r['dex'],'offset_cu':call['offset_cu'],'target':t,'kind':kind})
        modules.append({'module_label':label,'roots':roots,'method_definitions':len(selected),
                        'explicit_invoke_sites':sum(len(r['calls']) for r in selected),
                        'associations':associations,'semantic_status':'entry/call-site index; full UI/state/asynchronous behavior not claimed'})
    version_files=[]
    with zipfile.ZipFile(SOURCE/'apk/com.panasonic.jp.lumixlab-22.apk') as z:
        for n in z.namelist():
            if n.startswith('META-INF/') and n.endswith('.version'):
                b=z.read(n);text=b.decode('utf-8',errors='replace').strip()
                version_files.append({'path':n,'sha256':sha(b),'declared_version':text if re.fullmatch(r'[\w.+:-]{1,100}',text) else '<not published>'})
    unresolved=load(ROOT/'analysis/lab_stage1_20261015/results/jadx_failures.json')
    triage=[]
    for row in unresolved['methods']:
        m=row['method'];status='structural CFG retained; full semantic review pending'
        if m.startswith('Ll0/h;->D('):status='new partial semantic recovery: PNG chunk copying/replacement + EXIF/XMP writer calls; exceptional/malformed-input behavior not fully restored'
        triage.append({'method':m,'dex':row['dex'],'location':row['location'],'status':status})
    save(RESULTS/'module_entries.json.gz',{'modules':modules,'third_party_version_declarations':version_files,
         'classification_limits':'Package/class/version declarations identify bundled namespaces. Obfuscated package ownership and exact upstream binary provenance remain unverified.'},True)
    save(RESULTS/'failed_method_progress.json',{'error_events':42,'distinct_methods':24,'methods':triage})
    save(RESULTS/'semantic_aliases.json',{'policy':'Descriptive aliases only; original descriptors/addresses retained, no APK mutation',
         'aliases':[{'original':'Ll0/h;->D(Ljava/io/BufferedInputStream;Ljava/io/BufferedOutputStream;)V','alias':'PNG_metadata_chunk_rewrite_partial','basis':'typed chunk reads/writes + actual L/M consumers'},
                    {'library':'libcube_merge.so','elf_va':'0x4dac','alias':'cube_input_file_reader_candidate','basis':'fopen -> header/body readers -> fclose'},
                    {'library':'libcube_merge.so','elf_va':'0x4e60','alias':'cube_composition_grid_writer','basis':'three-dimensional traversal, evaluator on second cube, writes output triplets'},
                    {'library':'libcube_merge.so','elf_va':'0x5714','alias':'cube_piecewise_interpolation_candidate','basis':'grid cell selection, six ordered coordinate regions, weighted corner data; mathematical reconstruction not independently tested'}]})
    print('Built',len(modules),'entry groups;',len(version_files),'bundled version declarations; 24 method statuses retained')
if __name__=='__main__':main()
