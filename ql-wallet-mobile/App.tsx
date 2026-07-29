import React, { useState, useEffect } from 'react';
import { SafeAreaView, View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Alert, StatusBar, Modal, PermissionsAndroid, Platform } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Dirs, FileSystem } from 'react-native-file-access';
import { pick, keepLocalCopy } from '@react-native-documents/picker';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { buildKeystore, decryptKeystore, bytesToHex, hexToBytes } from './crypto';
import { isSensorAvailable, simplePrompt } from '@sbaiahmed1/react-native-biometrics';
import { BarcodeScanner, CameraView } from '@pushpendersingh/react-native-scanner';
import QRCode from 'react-native-qrcode-svg';
import { gcm } from '@noble/ciphers/aes.js';

import { entropyToMnemonic, mnemonicToEntropy } from './mnemonic';

type Screen = 'home' | 'create' | 'unlock' | 'dashboard' | 'send' | 'receive' | 'history' | 'security' | 'profile' | 'beneficiaries' | 'biometrics' | 'qrscan';
const NODE_URL = 'https://quantum-lattice.futuristicai.co.za';

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}
function u64ToLEBytes(val: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = val;
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

type SentTx = { receiver: string; amount: string; time: string };
type Beneficiary = { name: string; address: string };

async function loadHistory(addr: string): Promise<SentTx[]> {
  try { const raw = await AsyncStorage.getItem('ql_sent_history_' + addr); return raw ? JSON.parse(raw) : []; }
  catch (e) { return []; }
}
async function saveHistory(addr: string, history: SentTx[]) {
  try { await AsyncStorage.setItem('ql_sent_history_' + addr, JSON.stringify(history)); } catch (e) {}
}
async function loadBeneficiaries(): Promise<Beneficiary[]> {
  try { const raw = await AsyncStorage.getItem('ql_beneficiaries'); return raw ? JSON.parse(raw) : []; }
  catch (e) { return []; }
}
async function saveBiometricSeed(seed: Uint8Array) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(seed);
  await AsyncStorage.setItem('ql_biometric_seed', JSON.stringify({
    key: Array.from(key), iv: Array.from(iv), ciphertext: Array.from(ciphertext),
  }));
}
async function loadBiometricSeed(): Promise<Uint8Array | null> {
  try {
    const raw = await AsyncStorage.getItem('ql_biometric_seed');
    if (!raw) return null;
    const data = JSON.parse(raw);
    const key = new Uint8Array(data.key);
    const iv = new Uint8Array(data.iv);
    const ciphertext = new Uint8Array(data.ciphertext);
    const cipher = gcm(key, iv);
    return cipher.decrypt(ciphertext);
  } catch (e) { return null; }
}
async function hasBiometricSeed(): Promise<boolean> {
  const raw = await AsyncStorage.getItem('ql_biometric_seed');
  return !!raw;
}
async function clearBiometricSeed() {
  await AsyncStorage.removeItem('ql_biometric_seed');
}

async function saveBeneficiaries(list: Beneficiary[]) {
  try { await AsyncStorage.setItem('ql_beneficiaries', JSON.stringify(list)); } catch (e) {}
}

function PasswordInput({ value, onChangeText, placeholder }: { value: string; onChangeText: (t: string) => void; placeholder: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <View style={styles.passwordWrap}>
      <TextInput
        style={styles.passwordInput}
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor="#5b5878"
        secureTextEntry={!visible}
      />
      <TouchableOpacity style={styles.eyeBtn} onPress={() => setVisible(!visible)}>
        <Text style={styles.eyeBtnText}>{visible ? '🙈' : '👁️'}</Text>
      </TouchableOpacity>
    </View>
  );
}

function Header({ title, onBack, onMenu }: { title: string; onBack?: () => void; onMenu?: () => void }) {
  return (
    <View style={styles.header}>
      {onBack ? (
        <TouchableOpacity onPress={onBack} style={styles.iconBtn} activeOpacity={0.6}><Text style={styles.iconBtnText}>←</Text></TouchableOpacity>
      ) : onMenu ? (
        <TouchableOpacity onPress={onMenu} style={styles.iconBtn} activeOpacity={0.6}><Text style={styles.iconBtnText}>☰</Text></TouchableOpacity>
      ) : <View style={styles.iconBtn} />}
      <Text style={styles.headerTitle}>{title}</Text>
      <View style={styles.iconBtn} />
    </View>
  );
}

async function ensureStoragePermission(): Promise<boolean> {
  if (Platform.OS !== 'android' || Platform.Version >= 29) {
    return true; // Not needed on iOS, or on modern Android (scoped storage handles it)
  }
  try {
    const granted = await PermissionsAndroid.request(
      PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
      {
        title: 'Storage Permission',
        message: 'Quantum-Lattice needs permission to save your keystore file to Downloads.',
        buttonPositive: 'Allow',
      }
    );
    return granted === PermissionsAndroid.RESULTS.GRANTED;
  } catch (e) {
    return false;
  }
}

function App() {
  const [screen, setScreen] = useState<Screen>('home');
  const [menuOpen, setMenuOpen] = useState(false);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [seedPhrase, setSeedPhrase] = useState('');
  const [keystoreJson, setKeystoreJson] = useState('');
  const [generating, setGenerating] = useState(false);
  const [savedMessage, setSavedMessage] = useState('');
  const [verifyCode, setVerifyCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyStatus, setVerifyStatus] = useState('');
  const [isVerified, setIsVerified] = useState(false);

  const [restorePhrase, setRestorePhrase] = useState('');
  const [unlocking, setUnlocking] = useState(false);
  const [pickedKeystore, setPickedKeystore] = useState<any>(null);
  const [unlockPassword, setUnlockPassword] = useState('');

  const [address, setAddress] = useState('');
  const [secretSeed, setSecretSeed] = useState<Uint8Array | null>(null);
  const [balance, setBalance] = useState<string | null>(null);
  const [chainHeight, setChainHeight] = useState<string | null>(null);
  const [loadingBalance, setLoadingBalance] = useState(false);
  const [resavingMessage, setResavingMessage] = useState('');

  const [receiverAddress, setReceiverAddress] = useState('');
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [biometricUnlocking, setBiometricUnlocking] = useState(false);

  useEffect(() => {
    isSensorAvailable()
      .then(info => setBiometricAvailable(info.available))
      .catch(() => setBiometricAvailable(false));
    hasBiometricSeed().then(setBiometricEnabled);
  }, []);

  useEffect(() => {
    if (screen !== 'qrscan') return;

    let cancelled = false;
    (async () => {
      const granted = await BarcodeScanner.hasCameraPermission() || await BarcodeScanner.requestCameraPermission();
      if (!granted || cancelled) {
        if (!granted) Alert.alert('Camera permission needed', 'Allow camera access to scan a QR code.');
        return;
      }
      await BarcodeScanner.startScanning((barcodes) => {
        if (cancelled || barcodes.length === 0) return;
        setReceiverAddress(barcodes[0].data);
        BarcodeScanner.stopScanning();
        setScreen('send');
      });
    })();

    return () => {
      cancelled = true;
      BarcodeScanner.stopScanning().catch(() => {});
    };
  }, [screen]);

  async function handleBiometricQuickUnlock() {
    setBiometricUnlocking(true);
    try {
      const authed = await simplePrompt('Unlock your Quantum-Lattice wallet');
      if (!authed) { setBiometricUnlocking(false); return; }
      const seed = await loadBiometricSeed();
      if (!seed) {
        Alert.alert('Not set up', 'Biometric quick-unlock is not currently set up.');
        setBiometricUnlocking(false);
        return;
      }
      const keys = ml_dsa65.keygen(seed);
      setAddress(bytesToHex(keys.publicKey));
      setSecretSeed(seed);
      setScreen('dashboard');
    } catch (e: any) {
      Alert.alert('Could not unlock', e.message || String(e));
    } finally {
      setBiometricUnlocking(false);
    }
  }

  async function handleEnableBiometric() {
    Alert.alert('Debug', 'secretSeed is: ' + (secretSeed ? 'a Uint8Array of length ' + secretSeed.length : 'null/undefined'));
    if (!secretSeed) return;
    try {
      const authed = await simplePrompt('Confirm your fingerprint or face to enable quick-unlock');
      if (!authed) return;
      Alert.alert('Debug', 'About to call saveBiometricSeed...');
      await saveBiometricSeed(secretSeed);
      setBiometricEnabled(true);
      Alert.alert('Enabled', 'Biometric quick-unlock is now set up on this device.');
    } catch (e: any) {
      Alert.alert('Could not enable', e.message || String(e));
    }
  }

  async function handleDisableBiometric() {
    await clearBiometricSeed();
    setBiometricEnabled(false);
    Alert.alert('Disabled', 'Biometric quick-unlock has been turned off.');
  }
  const [sendAmount, setSendAmount] = useState('');
  const [sending, setSending] = useState(false);
  const [sendStatus, setSendStatus] = useState('');

  const [sentHistory, setSentHistory] = useState<SentTx[]>([]);
  const [realHistory, setRealHistory] = useState<Array<{ direction: string; counterparty: string; amount_ql: number; block_height: number }>>([]);
  const [beneficiaries, setBeneficiaries] = useState<Beneficiary[]>([]);
  const [newBenName, setNewBenName] = useState('');
  const [newBenAddress, setNewBenAddress] = useState('');

  const [sigTestResult, setSigTestResult] = useState<{ sigLen: number; pubLen: number; message: string; first64Hex: string } | null>(null);
  const [profileName, setProfileName] = useState('');
  const [profileEmail, setProfileEmail] = useState('');

  async function loadRealHistory(addr: string) {
    try {
      const res = await fetch(NODE_URL + '/api/transactions?address=' + addr);
      const data = await res.json();
      const txs = (data.transactions || []).slice().sort((a: any, b: any) => b.block_height - a.block_height);
      setRealHistory(txs);
    } catch (e) {
      // Leave whatever local sent-history was already showing.
    }
  }

  async function fetchDashboardData(addr: string) {
    setLoadingBalance(true);
    try {
      const balRes = await fetch(NODE_URL + '/api/balance?address=' + addr);
      const bal = await balRes.json();
      setBalance(Number(bal.balance_ql).toLocaleString(undefined, { maximumFractionDigits: 4 }));
      const infoRes = await fetch(NODE_URL + '/api/json');
      const info = await infoRes.json();
      setChainHeight(Number(info.chain_height).toLocaleString());
    } catch (e) {
      setBalance('Could not load');
    } finally {
      setLoadingBalance(false);
    }
  }

  useEffect(() => {
    if (screen === 'dashboard' && address) {
      fetchDashboardData(address);
      loadRealHistory(address);
      loadHistory(address).then(setSentHistory);
      loadBeneficiaries().then(setBeneficiaries);
      setProfileName(name);
      setProfileEmail(email);
    }
  }, [screen, address]);

  function handleGenerate() {
    if (password.length < 10) { Alert.alert('Password too short', 'Please use at least 10 characters.'); return; }
    setGenerating(true);
    setTimeout(async () => {
      try {
        const seed = randomBytes(32);
        const keys = ml_dsa65.keygen(seed);
        const keystore = buildKeystore(keys.publicKey, seed, password);
        const phrase = entropyToMnemonic(seed);
        const addr = bytesToHex(keys.publicKey);
        setAddress(addr);
        setSecretSeed(seed);
        setSeedPhrase(phrase);
        setKeystoreJson(JSON.stringify(keystore, null, 2));

        if (email) {
          try {
            const body = JSON.stringify({ email, full_name: name, address: addr });
            await fetch(NODE_URL + '/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
            setVerifyStatus('A verification code was sent to ' + email);
          } catch (e) {
            setVerifyStatus('Could not reach the node — you can verify later from the menu.');
          }
        }
      } catch (e: any) {
        Alert.alert('Error generating wallet', e.message || String(e));
      } finally {
        setGenerating(false);
      }
    }, 50);
  }

  async function handleVerifyCode() {
    if (!/^\d{6}$/.test(verifyCode)) { Alert.alert('Invalid code', 'Enter the 6-digit code from your email.'); return; }
    setVerifying(true);
    try {
      const body = JSON.stringify({ email: email || profileEmail, code: verifyCode });
      const res = await fetch(NODE_URL + '/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const rawText = await res.text();
      let resJson: any = {};
      try { resJson = JSON.parse(rawText); } catch (e) { resJson = { error: rawText }; }
      if (res.ok) { setIsVerified(true); setVerifyStatus('✓ Verified!'); }
      else { throw new Error(resJson.error || 'Verification failed.'); }
    } catch (e: any) {
      Alert.alert('Could not verify', e.message || String(e));
    } finally {
      setVerifying(false);
    }
  }

  async function handleResendCode() {
    try {
      const body = JSON.stringify({ email });
      await fetch(NODE_URL + '/api/resend-verification', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      setVerifyStatus('A new code was sent to ' + email);
    } catch (e: any) {
      Alert.alert('Could not resend', e.message || String(e));
    }
  }

  async function handleSaveKeystore() {
    try {
      const hasPermission = await ensureStoragePermission();
      if (!hasPermission) {
        Alert.alert('Permission needed', 'Storage permission is required to save the keystore file.');
        return;
      }
      const filename = 'ql-wallet-' + address.slice(0, 10) + '.json';
      const tempPath = Dirs.CacheDir + '/' + filename;
      await FileSystem.writeFile(tempPath, keystoreJson, 'utf8');
      await FileSystem.cpExternal(tempPath, filename, 'downloads');
      setSavedMessage('✓ Saved to Downloads: ' + filename);
    } catch (e: any) {
      Alert.alert('Could not save keystore', e.message || String(e));
    }
  }

  function handleUnlockWithPhrase() {
    setUnlocking(true);
    setTimeout(() => {
      try {
        const seed = mnemonicToEntropy(restorePhrase);
        const keys = ml_dsa65.keygen(seed);
        setAddress(bytesToHex(keys.publicKey));
        setSecretSeed(seed);
        setScreen('dashboard');
      } catch (e: any) {
        Alert.alert('Could not unlock', e.message || String(e));
      } finally {
        setUnlocking(false);
      }
    }, 50);
  }

  async function handlePickKeystoreFile() {
    try {
      const [result] = await pick();
      const [copyResult] = await keepLocalCopy({ files: [{ uri: result.uri, fileName: result.name ?? 'keystore.json' }], destination: 'cachesDirectory' });
      if (copyResult.status !== 'success') throw new Error('Could not access the selected file.');
      const content = await FileSystem.readFile(copyResult.localUri, 'utf8');
      setPickedKeystore(JSON.parse(content));
    } catch (e: any) {
      Alert.alert('Could not read keystore file', e.message || String(e));
    }
  }

  function handleUnlockWithKeystore() {
    if (!pickedKeystore) return;
    setUnlocking(true);
    setTimeout(() => {
      try {
        const seed = decryptKeystore(pickedKeystore, unlockPassword);
        const keys = ml_dsa65.keygen(seed);
        const derivedAddress = bytesToHex(keys.publicKey);
        if (derivedAddress !== pickedKeystore.address) throw new Error('Incorrect password.');
        setAddress(derivedAddress);
        setSecretSeed(seed);
        setScreen('dashboard');

        if (pickedKeystore.kdf_iterations > 25000) {
          setTimeout(() => {
            Alert.alert(
              'Speed up future unlocks?',
              'This keystore uses older, slower settings. Re-save it with faster mobile settings? Your password stays the same, and this only affects unlocking on this device.',
              [
                { text: 'Not now', style: 'cancel' },
                {
                  text: 'Re-save',
                  onPress: () => {
                    setResavingMessage('Re-saving with faster settings — this takes about a minute, please wait...');
                    setTimeout(async () => {
                      try {
                        const hasPermission = await ensureStoragePermission();
                        if (!hasPermission) {
                          setResavingMessage('');
                          Alert.alert('Permission needed', 'Storage permission is required to save the keystore file.');
                          return;
                        }
                        const upgraded = buildKeystore(keys.publicKey, seed, unlockPassword);
                        const filename = 'ql-wallet-' + derivedAddress.slice(0, 10) + '-fast.json';
                        const tempPath = Dirs.CacheDir + '/' + filename;
                        await FileSystem.writeFile(tempPath, JSON.stringify(upgraded, null, 2), 'utf8');
                        await FileSystem.cpExternal(tempPath, filename, 'downloads');
                        setResavingMessage('');
                        Alert.alert('Done', 'Saved a faster keystore to Downloads as:\n' + filename);
                      } catch (e: any) {
                        setResavingMessage('');
                        Alert.alert('Could not re-save', e.message || String(e));
                      }
                    }, 50);
                  },
                },
              ]
            );
          }, 500);
        }
      } catch (e: any) {
        Alert.alert('Could not unlock', 'Incorrect password, or this keystore file is corrupted.');
      } finally {
        setUnlocking(false);
      }
    }, 50);
  }

  function handleSend() {
    if (!secretSeed) return;
    if (!receiverAddress || !sendAmount) { Alert.alert('Missing info', 'Enter a recipient and amount.'); return; }
    setSending(true);
    setSendStatus('Signing transaction...');
    setTimeout(async () => {
      try {
        const receiverBytes = hexToBytes(receiverAddress);
        const amountQL = parseFloat(sendAmount);
        if (isNaN(amountQL) || amountQL <= 0) throw new Error('Enter a valid amount greater than 0.');
        const amountSmallest = Math.round(amountQL * 100000000);
        const keys = ml_dsa65.keygen(secretSeed);
        const amountBytes = u64ToLEBytes(BigInt(amountSmallest));
        const message = concatBytes(keys.publicKey, receiverBytes, amountBytes);
        const signature = ml_dsa65.sign(message, keys.secretKey);
        setSendStatus('Broadcasting to node...');
        const body = JSON.stringify({ sender: bytesToHex(keys.publicKey), receiver: bytesToHex(receiverBytes), amount: amountSmallest, signature: bytesToHex(signature) });
        const res = await fetch(NODE_URL + '/api/submit_tx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
        const rawText = await res.text();
        let resJson: any = {};
        try { resJson = JSON.parse(rawText); } catch (e) { resJson = { note: rawText }; }
        if (res.ok) {
          setSendStatus('✓ Sent! Will confirm in the next block.');
          const newEntry: SentTx = { receiver: receiverAddress, amount: sendAmount, time: new Date().toLocaleString() };
          const updated = [newEntry, ...sentHistory].slice(0, 100);
          setSentHistory(updated);
          saveHistory(address, updated);
          setReceiverAddress('');
          setSendAmount('');
          setTimeout(() => { setScreen('dashboard'); setSendStatus(''); fetchDashboardData(address); }, 2000);
        } else {
          setSendStatus('✕ Failed: ' + (resJson.error || resJson.note || 'Unknown error'));
        }
      } catch (e: any) {
        setSendStatus('✕ Error: ' + (e.message || String(e)));
      } finally {
        setSending(false);
      }
    }, 50);
  }

  async function handleAddBeneficiary() {
    if (!newBenName || !newBenAddress) { Alert.alert('Missing info', 'Enter both a name and an address.'); return; }
    const updated = [...beneficiaries, { name: newBenName, address: newBenAddress }];
    setBeneficiaries(updated);
    saveBeneficiaries(updated);
    setNewBenName('');
    setNewBenAddress('');
  }
  async function handleDeleteBeneficiary(index: number) {
    const updated = beneficiaries.filter((_, i) => i !== index);
    setBeneficiaries(updated);
    saveBeneficiaries(updated);
  }

  function handleRunSigTest() {
    if (!secretSeed) return;
    try {
      const keys = ml_dsa65.keygen(secretSeed);
      const messageText = 'Quantum-Lattice self-test: ' + new Date().toISOString();
      const testMessage = new TextEncoder().encode(messageText);
      const sig = ml_dsa65.sign(testMessage, keys.secretKey);
      const first64Hex = bytesToHex(sig.slice(0, 64));
      setSigTestResult({ sigLen: sig.length, pubLen: keys.publicKey.length, message: messageText, first64Hex });
    } catch (e: any) {
      Alert.alert('Test failed', e.message || String(e));
    }
  }

  function handleLock() {
    setAddress(''); setSecretSeed(null); setBalance(null); setChainHeight(null);
    setName(''); setEmail(''); setPassword(''); setSeedPhrase(''); setKeystoreJson('');
    setSavedMessage(''); setRestorePhrase(''); setPickedKeystore(null); setUnlockPassword('');
    setResavingMessage(''); setSentHistory([]); setSigTestResult(null); setIsVerified(false);
    setVerifyCode(''); setVerifyStatus(''); setMenuOpen(false); setScreen('home');
  }

  if (screen === 'home') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <View style={styles.centerBox}>
          <View style={styles.markCircle}><Text style={styles.markText}>QL</Text></View>
          <Text style={styles.title}>Quantum-Lattice</Text>
          <Text style={styles.subtitle}>Post-quantum secure wallet</Text>
          {biometricEnabled ? (
            <TouchableOpacity style={styles.button} onPress={handleBiometricQuickUnlock} disabled={biometricUnlocking} activeOpacity={0.8}>
              <Text style={styles.buttonText}>{biometricUnlocking ? 'Unlocking...' : '👆  Quick Unlock'}</Text>
            </TouchableOpacity>
          ) : null}
          <TouchableOpacity style={biometricEnabled ? [styles.button, styles.buttonGhost] : styles.button} onPress={() => setScreen('create')} activeOpacity={0.8}>
            <Text style={biometricEnabled ? styles.buttonTextGhost : styles.buttonText}>Create New Wallet</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={() => setScreen('unlock')} activeOpacity={0.8}><Text style={styles.buttonTextGhost}>Unlock Existing Wallet</Text></TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  if (screen === 'create') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Create Wallet" onBack={!address ? () => setScreen('home') : undefined} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {!address ? (
            <>
              <Text style={styles.label}>Name (optional)</Text>
              <TextInput style={styles.input} value={name} onChangeText={setName} placeholder="Your name" placeholderTextColor="#5b5878" />
              <Text style={styles.label}>Email (optional — for verification)</Text>
              <TextInput style={styles.input} value={email} onChangeText={setEmail} placeholder="you@example.com" placeholderTextColor="#5b5878" autoCapitalize="none" />
              <Text style={styles.label}>Password</Text>
              <PasswordInput value={password} onChangeText={setPassword} placeholder="At least 10 characters" />
              <TouchableOpacity style={styles.button} onPress={handleGenerate} disabled={generating} activeOpacity={0.8}>
                <Text style={styles.buttonText}>{generating ? 'Generating...' : 'Generate Wallet'}</Text>
              </TouchableOpacity>
            </>
          ) : (
            <>
              <View style={styles.resultBox}><Text style={styles.resultLabel}>YOUR ADDRESS</Text><Text style={styles.resultText} selectable>{address}</Text></View>
              <View style={[styles.resultBox, styles.warnBox]}><Text style={styles.resultLabel}>⚠️ SEED PHRASE — WRITE THIS DOWN ON PAPER</Text><Text style={styles.resultText} selectable>{seedPhrase}</Text></View>

              {email && !isVerified ? (
                <View style={styles.resultBox}>
                  <Text style={styles.resultLabel}>VERIFY YOUR EMAIL</Text>
                  {verifyStatus ? <Text style={styles.verifyStatusText}>{verifyStatus}</Text> : null}
                  <TextInput style={[styles.input, { marginTop: 10 }]} value={verifyCode} onChangeText={setVerifyCode} placeholder="6-digit code" placeholderTextColor="#5b5878" keyboardType="number-pad" maxLength={6} />
                  <TouchableOpacity style={styles.button} onPress={handleVerifyCode} disabled={verifying} activeOpacity={0.8}><Text style={styles.buttonText}>{verifying ? 'Verifying...' : 'Verify'}</Text></TouchableOpacity>
                  <TouchableOpacity onPress={handleResendCode}><Text style={styles.linkText}>Resend code</Text></TouchableOpacity>
                </View>
              ) : null}

              <TouchableOpacity style={styles.button} onPress={handleSaveKeystore} activeOpacity={0.8}><Text style={styles.buttonText}>⬇️  Save Keystore File</Text></TouchableOpacity>
              {savedMessage ? <Text style={styles.savedText}>{savedMessage}</Text> : null}
              <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={() => setScreen('dashboard')} activeOpacity={0.8}><Text style={styles.buttonTextGhost}>Continue to Wallet →</Text></TouchableOpacity>
            </>
          )}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'unlock') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Unlock Wallet" onBack={() => { setPickedKeystore(null); setScreen('home'); }} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {!pickedKeystore ? (
            <>
              <TouchableOpacity style={styles.button} onPress={handlePickKeystoreFile} activeOpacity={0.8}><Text style={styles.buttonText}>📄  Choose Keystore File</Text></TouchableOpacity>
              <Text style={styles.orText}>— OR —</Text>
              <Text style={styles.label}>24-word seed phrase</Text>
              <TextInput style={[styles.input, styles.multilineInput]} value={restorePhrase} onChangeText={setRestorePhrase} placeholder="word1 word2 word3 ..." placeholderTextColor="#5b5878" multiline autoCapitalize="none" />
              <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={handleUnlockWithPhrase} disabled={unlocking} activeOpacity={0.8}><Text style={styles.buttonTextGhost}>{unlocking ? 'Unlocking...' : 'Unlock with Seed Phrase'}</Text></TouchableOpacity>
            </>
          ) : (
            <>
              <View style={styles.resultBox}><Text style={styles.resultLabel}>KEYSTORE LOADED — ADDRESS</Text><Text style={styles.resultText} selectable>{pickedKeystore.address}</Text></View>
              <Text style={styles.label}>Password</Text>
              <PasswordInput value={unlockPassword} onChangeText={setUnlockPassword} placeholder="Enter your password" />
              <TouchableOpacity style={styles.button} onPress={handleUnlockWithKeystore} disabled={unlocking} activeOpacity={0.8}><Text style={styles.buttonText}>{unlocking ? 'Unlocking...' : 'Unlock'}</Text></TouchableOpacity>
              <TouchableOpacity onPress={() => setPickedKeystore(null)}><Text style={styles.linkText}>Choose a different file</Text></TouchableOpacity>
            </>
          )}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'send') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Send QL" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {beneficiaries.length > 0 ? (
            <>
              <Text style={styles.label}>Quick pick</Text>
              <View style={styles.benRow}>
                {beneficiaries.map((b, i) => (
                  <TouchableOpacity key={i} style={styles.benChip} onPress={() => setReceiverAddress(b.address)}><Text style={styles.benChipText}>{b.name}</Text></TouchableOpacity>
                ))}
              </View>
            </>
          ) : null}
          <Text style={styles.label}>Recipient address</Text>
          <TextInput style={[styles.input, styles.multilineInput]} value={receiverAddress} onChangeText={setReceiverAddress} placeholder="Recipient's full address" placeholderTextColor="#5b5878" multiline autoCapitalize="none" />
          <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={() => setScreen('qrscan')} activeOpacity={0.8}>
            <Text style={styles.buttonTextGhost}>📷  Scan QR to Pay</Text>
          </TouchableOpacity>
          <Text style={styles.label}>Amount (QL)</Text>
          <TextInput style={styles.input} value={sendAmount} onChangeText={setSendAmount} placeholder="0.00" placeholderTextColor="#5b5878" keyboardType="decimal-pad" />
          <TouchableOpacity style={styles.button} onPress={handleSend} disabled={sending} activeOpacity={0.8}><Text style={styles.buttonText}>{sending ? 'Sending...' : 'Send'}</Text></TouchableOpacity>
          {sendStatus ? <Text style={styles.savedText}>{sendStatus}</Text> : null}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'receive') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Receive QL" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          <Text style={styles.receiveHint}>Share this address with anyone sending you QL.</Text>
          <View style={styles.resultBox}><Text style={styles.resultLabel}>YOUR ADDRESS</Text><Text style={styles.resultText} selectable>{address}</Text></View>
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'history') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Transaction History" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {realHistory.length > 0 ? (
            realHistory.map((tx, i) => (
              <View key={i} style={[styles.resultBox, styles.activityRow, { marginTop: i === 0 ? 0 : 12, borderTopWidth: 0 }]}>
                <Text style={[styles.activityAmount, tx.direction === 'received' ? { color: '#34d399' } : null]}>
                  {tx.direction === 'sent' ? '-' : '+'}{tx.amount_ql} QL
                </Text>
                <Text style={styles.activityTo}>{tx.direction === 'sent' ? 'to ' : 'from '}{tx.counterparty}</Text>
                <Text style={styles.activityTime}>Block #{tx.block_height}</Text>
              </View>
            ))
          ) : <Text style={styles.emptyText}>No transactions yet.</Text>}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'beneficiaries') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Saved Beneficiaries" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {beneficiaries.map((b, i) => (
            <View key={i} style={styles.benListRow}>
              <View><Text style={styles.benName}>{b.name}</Text><Text style={styles.benAddr} numberOfLines={1}>{b.address.slice(0, 24)}...</Text></View>
              <TouchableOpacity onPress={() => handleDeleteBeneficiary(i)}><Text style={styles.deleteText}>✕</Text></TouchableOpacity>
            </View>
          ))}
          {beneficiaries.length === 0 ? <Text style={styles.emptyText}>No saved beneficiaries yet.</Text> : null}
          <Text style={styles.label}>Add new</Text>
          <TextInput style={styles.input} value={newBenName} onChangeText={setNewBenName} placeholder="Name" placeholderTextColor="#5b5878" />
          <TextInput style={[styles.input, styles.multilineInput, { marginTop: 8 }]} value={newBenAddress} onChangeText={setNewBenAddress} placeholder="Address" placeholderTextColor="#5b5878" multiline autoCapitalize="none" />
          <TouchableOpacity style={styles.button} onPress={handleAddBeneficiary} activeOpacity={0.8}><Text style={styles.buttonText}>+ Add Beneficiary</Text></TouchableOpacity>
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'security') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Quantum Security" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          <Text style={styles.receiveHint}>
            Your key is built on ML-DSA-65 (FIPS 204) — designed to resist attacks from quantum computers that will
            eventually break the cryptography behind Bitcoin and Ethereum.
          </Text>
          <View style={styles.resultBox}>
            <Text style={styles.resultLabel}>KEY SIZE COMPARISON</Text>
            <View style={styles.compareRow}><Text style={styles.compareLabel}>Your key (ML-DSA-65)</Text><Text style={styles.compareValue}>1,952 bytes</Text></View>
            <View style={styles.compareRow}><Text style={styles.compareLabel}>Typical ECDSA key (Bitcoin/ETH)</Text><Text style={styles.compareValue}>32 bytes</Text></View>
          </View>
          <TouchableOpacity style={styles.button} onPress={handleRunSigTest} activeOpacity={0.8}><Text style={styles.buttonText}>Run Live Signature Self-Test</Text></TouchableOpacity>
          {sigTestResult ? (
            <View style={styles.resultBox}>
              <Text style={styles.resultLabel}>REAL SIGNATURE PRODUCED BY YOUR OWN KEY, JUST NOW</Text>
              <Text style={styles.sigDetailLabel}>Message signed:</Text>
              <Text style={styles.sigDetailValue}>"{sigTestResult.message}"</Text>
              <Text style={styles.sigDetailLabel}>Signature size:</Text>
              <Text style={styles.sigDetailValue}>{sigTestResult.sigLen.toLocaleString()} bytes</Text>
              <Text style={styles.sigDetailLabel}>First 64 bytes:</Text>
              <Text style={styles.resultText} selectable>{sigTestResult.first64Hex}…</Text>
              <Text style={styles.sigFooterText}>
                This is a genuine ML-DSA-65 signature from your real secret key — anyone with your public key could independently verify it.
              </Text>
            </View>
          ) : null}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'profile') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Profile" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          <Text style={styles.label}>Name</Text>
          <TextInput style={styles.input} value={profileName} onChangeText={setProfileName} placeholder="Your name" placeholderTextColor="#5b5878" />
          <TouchableOpacity style={[styles.button, styles.buttonGhost]} activeOpacity={0.8} onPress={() => { setName(profileName); Alert.alert('Updated', 'Name updated for this session.'); }}>
            <Text style={styles.buttonTextGhost}>Update Name</Text>
          </TouchableOpacity>

          <Text style={[styles.label, { marginTop: 28 }]}>Email</Text>
          <TextInput style={styles.input} value={profileEmail} onChangeText={setProfileEmail} placeholder="you@example.com" placeholderTextColor="#5b5878" autoCapitalize="none" />
          <TouchableOpacity
            style={styles.button}
            activeOpacity={0.8}
            onPress={async () => {
              if (!profileEmail) { Alert.alert('Enter an email first'); return; }
              try {
                const body = JSON.stringify({ email: profileEmail, full_name: profileName, address });
                await fetch(NODE_URL + '/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
                setEmail(profileEmail);
                Alert.alert('Sent', 'A verification code was sent to ' + profileEmail);
              } catch (e: any) {
                Alert.alert('Could not send', e.message || String(e));
              }
            }}
          >
            <Text style={styles.buttonText}>Send Verification Email</Text>
          </TouchableOpacity>

          <Text style={styles.label}>6-digit code</Text>
          <TextInput style={styles.input} value={verifyCode} onChangeText={setVerifyCode} placeholder="123456" placeholderTextColor="#5b5878" keyboardType="number-pad" maxLength={6} />
          <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={handleVerifyCode} disabled={verifying} activeOpacity={0.8}><Text style={styles.buttonTextGhost}>{verifying ? 'Verifying...' : 'Verify'}</Text></TouchableOpacity>
          {isVerified ? <Text style={styles.savedText}>✓ Verified!</Text> : null}
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === 'qrscan') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Scan QR Code" onBack={() => setScreen('send')} />
        <View style={{ flex: 1 }}>
          <CameraView style={{ flex: 1 }} />
          <View style={styles.qrHintBar}>
            <Text style={styles.qrHintText}>Point your camera at a QL address QR code</Text>
          </View>
        </View>
      </SafeAreaView>
    );
  }

  if (screen === 'biometrics') {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="light-content" backgroundColor="#07070d" />
        <Header title="Biometric Unlock" onBack={() => setScreen('dashboard')} />
        <ScrollView contentContainerStyle={styles.scroll}>
          {!biometricAvailable ? (
            <Text style={styles.receiveHint}>No fingerprint or face sensor was detected on this device.</Text>
          ) : biometricEnabled ? (
            <>
              <Text style={styles.receiveHint}>Biometric quick-unlock is currently enabled on this device.</Text>
              <TouchableOpacity style={[styles.button, styles.buttonGhost]} onPress={handleDisableBiometric} activeOpacity={0.8}>
                <Text style={styles.buttonTextGhost}>Disable Biometric Unlock</Text>
              </TouchableOpacity>
            </>
          ) : (
            <>
              <Text style={styles.receiveHint}>
                Enable this to unlock your wallet quickly next time using your fingerprint or face, instead of
                re-entering your password or seed phrase. Your password and keystore file remain the real, full
                security either way.
              </Text>
              <TouchableOpacity style={styles.button} onPress={handleEnableBiometric} activeOpacity={0.8}>
                <Text style={styles.buttonText}>Enable Biometric Unlock</Text>
              </TouchableOpacity>
            </>
          )}
        </ScrollView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#07070d" />
      <Header title="Wallet" onMenu={() => setMenuOpen(true)} />

      <Modal visible={menuOpen} transparent animationType="fade" onRequestClose={() => setMenuOpen(false)}>
        <TouchableOpacity style={styles.menuOverlay} activeOpacity={1} onPress={() => setMenuOpen(false)}>
          <View style={styles.menuPanel}>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('dashboard'); }}><Text style={styles.menuItemText}>Home</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('receive'); }}><Text style={styles.menuItemText}>Wallet Address</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('send'); }}><Text style={styles.menuItemText}>Send / Pay</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('history'); }}><Text style={styles.menuItemText}>Sent History</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('beneficiaries'); }}><Text style={styles.menuItemText}>Saved Beneficiaries</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('security'); }}><Text style={styles.menuItemText}>Quantum Security</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('profile'); }}><Text style={styles.menuItemText}>Profile / Verify Email</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); setScreen('biometrics'); }}><Text style={styles.menuItemText}>Biometric Unlock</Text></TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={() => { setMenuOpen(false); handleLock(); }}><Text style={[styles.menuItemText, { color: '#f26d6d' }]}>Lock Wallet</Text></TouchableOpacity>
          </View>
        </TouchableOpacity>
      </Modal>

      <ScrollView contentContainerStyle={styles.scroll}>
        {resavingMessage ? <Text style={styles.savedText}>{resavingMessage}</Text> : null}
        <View style={styles.balanceBox}>
          <Text style={styles.balanceLabel}>BALANCE</Text>
          <Text style={styles.balanceValue}>{loadingBalance ? '···' : (balance ?? '—')}</Text>
          <Text style={styles.balanceUnit}>QL</Text>
          <View style={styles.divider} />
          <Text style={styles.chainHeightText}>Chain height: {chainHeight ?? '...'}</Text>
          <TouchableOpacity onPress={() => fetchDashboardData(address)}><Text style={styles.linkText}>↻ Refresh</Text></TouchableOpacity>
        </View>

        <View style={styles.tabRow}>
          <TouchableOpacity style={styles.tabBtn} onPress={() => setScreen('send')} activeOpacity={0.8}><Text style={styles.tabIcon}>↑</Text><Text style={styles.tabLabel}>Send</Text></TouchableOpacity>
          <TouchableOpacity style={styles.tabBtn} onPress={() => setScreen('receive')} activeOpacity={0.8}><Text style={styles.tabIcon}>◈</Text><Text style={styles.tabLabel}>Receive</Text></TouchableOpacity>
          <TouchableOpacity style={styles.tabBtn} onPress={() => setScreen('history')} activeOpacity={0.8}><Text style={styles.tabIcon}>≡</Text><Text style={styles.tabLabel}>History</Text></TouchableOpacity>
        </View>

        <View style={styles.resultBox}>
          <Text style={styles.resultLabel}>RECENT ACTIVITY</Text>
          {realHistory.length > 0 ? (
            realHistory.slice(0, 3).map((tx, i) => (
              <View key={i} style={styles.activityRow}>
                <Text style={[styles.activityAmount, tx.direction === 'received' ? { color: '#34d399' } : null]}>
                  {tx.direction === 'sent' ? '-' : '+'}{tx.amount_ql} QL
                </Text>
                <Text style={styles.activityTo} numberOfLines={1}>
                  {tx.direction === 'sent' ? 'to ' : 'from '}{tx.counterparty.slice(0, 16)}...
                </Text>
              </View>
            ))
          ) : <Text style={styles.emptyText}>No transactions yet.</Text>}
          {realHistory.length > 3 ? <TouchableOpacity onPress={() => setScreen('history')}><Text style={styles.linkText}>View all →</Text></TouchableOpacity> : null}
        </View>

        <TouchableOpacity style={[styles.resultBox, { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }]} onPress={() => setScreen('security')} activeOpacity={0.8}>
          <View style={{ flex: 1 }}>
            <Text style={styles.resultLabel}>◆ QUANTUM SECURITY</Text>
            <Text style={styles.receiveHint}>Your key is 1,952 bytes — built to resist attacks that will eventually break Bitcoin and Ethereum.</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity style={styles.resultBox} activeOpacity={0.8} onPress={() => Alert.alert('Coming soon', 'Multi-account support is on the roadmap.')}>
          <Text style={styles.resultLabel}>+ ADD ACCOUNT</Text>
          <Text style={styles.receiveHint}>Coming soon</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#07070d' },
  scroll: { padding: 20, paddingBottom: 40 },
  centerBox: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24 },
  markCircle: { width: 72, height: 72, borderRadius: 36, backgroundColor: '#7c5cfc', alignItems: 'center', justifyContent: 'center', marginBottom: 20 },
  markText: { color: 'white', fontSize: 22, fontWeight: '800', letterSpacing: 1 },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 12, paddingTop: 16, paddingBottom: 8 },
  headerTitle: { color: '#eae8f5', fontSize: 17, fontWeight: '700' },
  iconBtn: { width: 36, height: 36, alignItems: 'center', justifyContent: 'center' },
  iconBtnText: { color: '#eae8f5', fontSize: 20 },
  title: { color: '#eae8f5', fontSize: 24, fontWeight: '800', marginBottom: 4, textAlign: 'center' },
  subtitle: { color: '#8b87a8', fontSize: 13, marginBottom: 40, textAlign: 'center' },
  label: { color: '#8b87a8', fontSize: 11, fontWeight: '700', marginBottom: 6, marginTop: 16, textTransform: 'uppercase', letterSpacing: 0.5 },
  input: { backgroundColor: '#0f1020', borderWidth: 1, borderColor: '#262842', borderRadius: 12, padding: 14, color: '#eae8f5', fontSize: 15 },
  multilineInput: { minHeight: 60, textAlignVertical: 'top' },
  passwordWrap: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#0f1020', borderWidth: 1, borderColor: '#262842', borderRadius: 12 },
  passwordInput: { flex: 1, padding: 14, color: '#eae8f5', fontSize: 15 },
  eyeBtn: { paddingHorizontal: 14 },
  eyeBtnText: { fontSize: 16 },
  button: { backgroundColor: '#7c5cfc', paddingVertical: 15, borderRadius: 14, alignItems: 'center', marginTop: 18, shadowColor: '#7c5cfc', shadowOpacity: 0.3, shadowRadius: 12, shadowOffset: { width: 0, height: 4 }, elevation: 4 },
  buttonGhost: { backgroundColor: 'transparent', borderWidth: 1.5, borderColor: '#7c5cfc', shadowOpacity: 0 },
  buttonText: { color: 'white', fontWeight: '700', fontSize: 15 },
  buttonTextGhost: { color: '#a78bfa', fontWeight: '700', fontSize: 15 },
  linkText: { color: '#8b87a8', textAlign: 'center', marginTop: 14, fontSize: 13 },
  orText: { color: '#5b5878', textAlign: 'center', marginVertical: 20, fontSize: 11, fontWeight: '700', letterSpacing: 1 },
  resultBox: { marginTop: 16, backgroundColor: '#14152a', borderRadius: 14, padding: 16, borderWidth: 1, borderColor: '#1e2038' },
  warnBox: { borderColor: '#f0b429' },
  resultLabel: { color: '#5b5878', fontSize: 10, fontWeight: '700', marginBottom: 8, letterSpacing: 0.5 },
  resultText: { color: '#22d3c5', fontSize: 12, fontFamily: 'monospace', lineHeight: 19 },
  savedText: { color: '#34d399', fontSize: 13, textAlign: 'center', marginTop: 14, marginBottom: 4 },
  verifyStatusText: { color: '#8b87a8', fontSize: 12, marginBottom: 6 },
  balanceBox: { backgroundColor: '#14152a', borderRadius: 20, padding: 28, alignItems: 'center', marginTop: 8, marginBottom: 16, borderWidth: 1, borderColor: '#1e2038' },
  balanceLabel: { color: '#5b5878', fontSize: 11, fontWeight: '700', letterSpacing: 1 },
  balanceValue: { color: '#eae8f5', fontSize: 36, fontWeight: '800', marginTop: 8 },
  balanceUnit: { color: '#7c5cfc', fontSize: 13, fontWeight: '700', marginTop: 2, marginBottom: 14 },
  divider: { width: '100%', height: 1, backgroundColor: '#1e2038', marginBottom: 12 },
  chainHeightText: { color: '#5b5878', fontSize: 12, marginBottom: 4 },
  tabRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 10 },
  tabBtn: { flex: 1, backgroundColor: '#14152a', borderRadius: 14, paddingVertical: 14, alignItems: 'center', borderWidth: 1, borderColor: '#1e2038' },
  tabIcon: { color: '#7c5cfc', fontSize: 18, marginBottom: 4 },
  tabLabel: { color: '#8b87a8', fontSize: 11, fontWeight: '700' },
  activityRow: { borderTopWidth: 1, borderTopColor: '#1e2038', paddingTop: 10, marginTop: 10 },
  activityAmount: { color: '#f26d6d', fontSize: 14, fontWeight: '700' },
  activityTo: { color: '#8b87a8', fontSize: 12, marginTop: 2 },
  activityTime: { color: '#5b5878', fontSize: 11, marginTop: 2 },
  emptyText: { color: '#5b5878', fontSize: 13, fontStyle: 'italic' },
  receiveHint: { color: '#8b87a8', fontSize: 12, marginTop: 4, lineHeight: 17 },
  menuOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)' },
  menuPanel: { backgroundColor: '#14152a', width: 260, height: '100%', paddingTop: 60, paddingHorizontal: 20, borderRightWidth: 1, borderRightColor: '#262842' },
  menuItem: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#1e2038' },
  menuItemText: { color: '#eae8f5', fontSize: 15, fontWeight: '600' },
  compareRow: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 6 },
  compareLabel: { color: '#8b87a8', fontSize: 13 },
  compareValue: { color: '#22d3c5', fontSize: 13, fontWeight: '700' },
  benRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginBottom: 8 },
  benChip: { backgroundColor: '#1e2038', paddingHorizontal: 14, paddingVertical: 8, borderRadius: 20 },
  benChipText: { color: '#a78bfa', fontSize: 12, fontWeight: '600' },
  qrBox: { backgroundColor: 'white', borderRadius: 16, padding: 20, alignItems: 'center', alignSelf: 'center', marginVertical: 16 },
  qrHintBar: { position: 'absolute', bottom: 40, left: 20, right: 20, backgroundColor: 'rgba(20,21,42,0.9)', borderRadius: 14, padding: 16, alignItems: 'center' },
  qrHintText: { color: '#eae8f5', fontSize: 13, fontWeight: '600' },
  benListRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 10, borderTopWidth: 1, borderTopColor: '#1e2038' },
  benName: { color: '#eae8f5', fontSize: 14, fontWeight: '600' },
  benAddr: { color: '#5b5878', fontSize: 11, marginTop: 2 },
  deleteText: { color: '#f26d6d', fontSize: 16 },
  sigDetailLabel: { color: '#5b5878', fontSize: 11, marginTop: 10, marginBottom: 3 },
  sigDetailValue: { color: '#eae8f5', fontSize: 12 },
  sigFooterText: { color: '#8b87a8', fontSize: 11, marginTop: 14, lineHeight: 16, fontStyle: 'italic' },
});

export default App;






















