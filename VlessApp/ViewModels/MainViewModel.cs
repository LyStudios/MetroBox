using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking.Vpn;
using Windows.Storage;
using VlessApp.Mvvm;
using VlessApp.Services;

namespace VlessApp.ViewModels
{
    public sealed class MainViewModel : ObservableObject
    {
        private readonly ProfileStore _profileStore;
        private readonly VpnService _vpnService;

        private readonly List<VlessProfile> _allProfiles = new List<VlessProfile>();
        private readonly Dictionary<string, bool> _groupExpansionStates = new Dictionary<string, bool>();
        private bool _pendingProfileChange;

        private VlessProfile _selectedProfile;
        private bool _isConnected;
        private TimeSpan _activeTime = TimeSpan.Zero;
        private string _statusText = "";
        private string _connectBtnText = "ПОДКЛЮЧИТЬ";
        private string _transportWarnText = "";
        private bool _hasTransportWarning;
        private bool _isAboutPageOpen;
        private bool _isHideAllVisible;
        private bool _isBusy;
        private CancellationTokenSource _groupPingCts;

        public MainViewModel(ProfileStore profileStore = null, VpnService vpnService = null)
        {
            _profileStore = profileStore ?? new ProfileStore();
            _vpnService = vpnService ?? new VpnService();

            GroupedProfiles = new ObservableCollection<ProfileGroup>();

            ToggleConnectCommand = new AsyncRelayCommand(ToggleConnectAsync, () => !IsBusy);
            CollapseAllCommand = new RelayCommand(CollapseAll);
            CheckConnectionCommand = new AsyncRelayCommand(CheckConnectionAsync);
            OpenSettingsCommand = new RelayCommand(() => IsAboutPageOpen = true);
            CloseSettingsCommand = new RelayCommand(() => IsAboutPageOpen = false);
        }

        // ==================== СВОЙСТВА ДЛЯ ПРИВЯЗКИ ====================

        public ObservableCollection<ProfileGroup> GroupedProfiles { get; }

        public List<VlessProfile> AllProfiles => _allProfiles;

        public VlessProfile SelectedProfile
        {
            get => _selectedProfile;
            set
            {
                if (SetProperty(ref _selectedProfile, value))
                {
                    OnSelectedProfileChanged(value);
                }
            }
        }

        public bool IsConnected
        {
            get => _isConnected;
            set
            {
                if (SetProperty(ref _isConnected, value))
                {
                    ConnectBtnText = value ? "ПОДКЛЮЧЕН" : "ПОДКЛЮЧИТЬ";
                    OnPropertyChanged(nameof(CanChangeSelection));
                }
            }
        }

        public bool CanChangeSelection => !IsConnected;

        public TimeSpan ActiveTime
        {
            get => _activeTime;
            set
            {
                if (SetProperty(ref _activeTime, value))
                {
                    OnPropertyChanged(nameof(ActiveTimeString));
                }
            }
        }

        public string ActiveTimeString => string.Format("{0:00}:{1:00}:{2:00}",
            (int)ActiveTime.TotalHours, ActiveTime.Minutes, ActiveTime.Seconds);

        public string StatusText
        {
            get => _statusText;
            set => SetProperty(ref _statusText, value);
        }

        public string ConnectBtnText
        {
            get => _connectBtnText;
            set => SetProperty(ref _connectBtnText, value);
        }

        public string TransportWarnText
        {
            get => _transportWarnText;
            set
            {
                if (SetProperty(ref _transportWarnText, value))
                {
                    HasTransportWarning = !string.IsNullOrEmpty(value);
                }
            }
        }

        public bool HasTransportWarning
        {
            get => _hasTransportWarning;
            set => SetProperty(ref _hasTransportWarning, value);
        }

        public bool IsAboutPageOpen
        {
            get => _isAboutPageOpen;
            set => SetProperty(ref _isAboutPageOpen, value);
        }

        public bool IsHideAllVisible
        {
            get => _isHideAllVisible;
            set => SetProperty(ref _isHideAllVisible, value);
        }

        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                if (SetProperty(ref _isBusy, value))
                {
                    ToggleConnectCommand.RaiseCanExecuteChanged();
                }
            }
        }

        // ==================== КОМАНДЫ ====================

        public AsyncRelayCommand ToggleConnectCommand { get; }
        public RelayCommand CollapseAllCommand { get; }
        public AsyncRelayCommand CheckConnectionCommand { get; }
        public RelayCommand OpenSettingsCommand { get; }
        public RelayCommand CloseSettingsCommand { get; }

        // ==================== СОБЫТИЯ ВЗАИМОДЕЙСТВИЯ С VIEW ====================

        internal Func<string, string, string, string, Task<bool>> RequestConfirmDialog;
        internal Func<string, string, Task> RequestMessageDialog;
        internal Func<int, Task> RequestImportReportDialog;
        internal Func<Exception, Task> RequestAmneziaErrorDialog;
        internal Func<AmneziaUnsupportedConfigException, Task> RequestUnsupportedConfigDialog;
        internal Action RequestNavigateToVpnSettings;
        internal Action RequestHardReset;

        // ==================== ИНИЦИАЛИЗАЦИЯ И СТАРТ ====================

        public async Task InitializeAsync()
        {
            await LoadProfilesAsync();
            RestoreLastSelectedProfile();
        }

        private async Task LoadProfilesAsync()
        {
            try
            {
                var list = await _profileStore.LoadAsync();
                _allProfiles.Clear();
                if (list != null)
                {
                    _allProfiles.AddRange(list);
                }
                AppLog.W($"[ПРОФИЛИ] Загружено при старте: {_allProfiles.Count} шт.");

                foreach (var p in _allProfiles)
                {
                    if (p.IsAmneziaRow && !p.AmneziaNotIssued &&
                        string.Equals(p.Security, "reality", StringComparison.OrdinalIgnoreCase) &&
                        string.IsNullOrEmpty(p.Sni))
                    {
                        p.AmneziaNotIssued = true;
                        p.Address = "";
                        p.CleanPingText = "";
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.W("[ПРОФИЛИ] ЗАГРУЗКА СОРВАЛАСЬ: " + ex);
            }

            UpdateGroupedUI();
        }

        private void RestoreLastSelectedProfile()
        {
            var localSettings = ApplicationData.Current.LocalSettings;
            string lastAddress = localSettings.Values["v_LastSelectedAddress"] as string;
            int? lastPort = localSettings.Values["v_LastSelectedPort"] as int?;

            if (!string.IsNullOrEmpty(lastAddress) && lastPort.HasValue)
            {
                var found = _allProfiles.FirstOrDefault(p => p.Address == lastAddress && p.Port == lastPort.Value);
                if (found != null)
                {
                    SelectProfile(found);
                }
            }
        }

        public void SelectProfile(VlessProfile profile)
        {
            if (profile == null || string.IsNullOrEmpty(profile.Address)) return;

            if (IsConnected)
            {
                _selectedProfile = profile;
                _pendingProfileChange = true;
                OnPropertyChanged(nameof(SelectedProfile));

                foreach (var p in _allProfiles)
                {
                    p.IsSelected = (p == profile);
                }

                StatusText = $"Выбран «{profile.Name}» (применится после отключения)";
                return;
            }

            _pendingProfileChange = false;
            _selectedProfile = profile;
            OnPropertyChanged(nameof(SelectedProfile));

            StatusText = $"Выбран: {profile.Name}";
            _vpnService.WriteSettings(profile);

            foreach (var p in _allProfiles)
            {
                p.IsSelected = (p == profile);
            }

            var localSettings = ApplicationData.Current.LocalSettings;
            localSettings.Values["v_LastSelectedAddress"] = profile.Address;
            localSettings.Values["v_LastSelectedPort"] = profile.Port;
        }

        private void OnSelectedProfileChanged(VlessProfile profile)
        {
            if (profile != null)
            {
                SelectProfile(profile);
            }
        }

        public async Task SaveProfilesAsync()
        {
            await _profileStore.SaveAsync(_allProfiles);
        }

        public void UpdateGroupedUI()
        {
            GroupedProfiles.Clear();
            var groups = _allProfiles
                .GroupBy(p => p.SubscriptionGroup)
                .OrderBy(g => g.Key == "Ручной импорт" || g.Key == "Импорт из буфера" ? 1 : 0)
                .Select(g =>
                {
                    var pg = new ProfileGroup { Key = g.Key };
                    if (_groupExpansionStates.TryGetValue(g.Key, out bool isExpanded))
                    {
                        pg.IsExpanded = isExpanded;
                    }
                    else
                    {
                        pg.IsExpanded = true;
                    }
                    pg.SetAllItems(g);
                    return pg;
                });

            foreach (var g in groups)
            {
                GroupedProfiles.Add(g);
            }

            UpdateHideAllButtonVisibility();
        }

        public void ToggleGroupExpansion(ProfileGroup group)
        {
            if (group == null) return;
            group.IsExpanded = !group.IsExpanded;
            _groupExpansionStates[group.Key] = group.IsExpanded;
            UpdateHideAllButtonVisibility();
        }

        public void CollapseAll()
        {
            foreach (var group in GroupedProfiles)
            {
                group.IsExpanded = false;
                _groupExpansionStates[group.Key] = false;
            }
            UpdateGroupedUI();
            UpdateHideAllButtonVisibility();
            StatusText = "Все группы свернуты";
        }

        private void UpdateHideAllButtonVisibility()
        {
            IsHideAllVisible = GroupedProfiles.Any(g => g.IsExpanded);
        }

        // ==================== ПОДКЛЮЧЕНИЕ / ОТКЛЮЧЕНИЕ ====================

        private async Task ToggleConnectAsync()
        {
            if (IsConnected)
            {
                await DisconnectAsync();
            }
            else
            {
                await ConnectAsync();
            }
        }

        public async Task ConnectAsync()
        {
            if (IsBusy) return;
            if (_selectedProfile == null)
            {
                StatusText = "Выберите профиль!";
                return;
            }

            AppLog.Section("ПОДКЛЮЧЕНИЕ: " + (_selectedProfile.Name ?? "?"));
            AppLog.W("  " + VlessProfile.Describe(_selectedProfile));

            string badSecurity = VlessProfile.WhySecurityWontWork(_selectedProfile);
            if (badSecurity != null) AppLog.W("  ВНИМАНИЕ: " + badSecurity);

            string badTransport = VlessProfile.WhyUnsupportedTransport(_selectedProfile);
            if (badTransport != null)
            {
                AppLog.W("  ОТКАЗ: " + badTransport);
                if (RequestMessageDialog != null)
                {
                    await RequestMessageDialog("Транспорт не поддерживается",
                        $"Профиль «{_selectedProfile.Name}»: {badTransport}.\n\nПоддерживаются: TCP (в том числе XTLS-Vision), WebSocket, gRPC и XHTTP/SplitHTTP.");
                }
                StatusText = "Подключение отменено (транспорт не поддерживается).";
                return;
            }

            if (_selectedProfile.IsShadowsocks &&
                !VlessProfile.IsSupportedSsMethod(_selectedProfile.Method))
            {
                if (RequestMessageDialog != null)
                {
                    await RequestMessageDialog("Шифр не поддерживается",
                        $"Shadowsocks-шифр «{_selectedProfile.Method}» не реализован.\n\nПоддерживаются: chacha20-ietf-poly1305, aes-128-gcm, aes-192-gcm, aes-256-gcm.");
                }
                AppLog.W("  ОТКАЗ: шифр Shadowsocks «" + (_selectedProfile.Method ?? "?") + "» не реализован");
                StatusText = "Подключение отменено (шифр Shadowsocks не поддерживается).";
                return;
            }

            if (string.Equals(_selectedProfile.Type, "xhttp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(_selectedProfile.Type, "splithttp", StringComparison.OrdinalIgnoreCase))
            {
                if (RequestConfirmDialog != null)
                {
                    bool ok = await RequestConfirmDialog("Ограниченная поддержка",
                        "Транспорт XHTTP реализован лишь частично и работает не со всеми серверами. " +
                        "Совместимость зависит от конфигурации сервера (режим и версия Reality). " +
                        "Если подключение не установится — используйте профиль с другим транспортом.",
                        "Всё равно подключиться", "Отмена");
                    if (!ok)
                    {
                        StatusText = "Подключение отменено.";
                        return;
                    }
                }
            }

            _vpnService.InvalidateProfileCache();
            var mine = await _vpnService.FindOwnProfileAsync();
            if (mine == null)
            {
                if (RequestConfirmDialog != null)
                {
                    bool openSettings = await RequestConfirmDialog("VPN-профиль не обнаружен",
                        "Добавьте профиль вручную в параметрах.", "Открыть настройки", "Закрыть");
                    if (openSettings)
                    {
                        RequestNavigateToVpnSettings?.Invoke();
                    }
                }
                return;
            }

            IsBusy = true;
            StatusText = "Подключение...";
            try
            {
                // Отключаем старую сессию перед стартом ТОЛЬКО если туннель реально ещё висит в системе.
                // Безусловный вызов DisconnectProfileAsync перед ConnectProfileAsync будит RasMan и
                // запускает 1250 мс TearDownAndExit фоновой задачи прямо посреди нового подключения.
                var priorState = await _vpnService.CheckStatusAsync();
                if (priorState != VpnManagementConnectionStatus.Disconnected || VpnService.IsVpnInterfaceActive())
                {
                    AppLog.W($"  предыдущий туннель ещё активен ({priorState}), останавливаю перед новым запуском...");
                    StatusText = "Перезапуск туннеля...";
                    await _vpnService.DisconnectProfileAsync(mine);

                    if (mine is VpnPlugInProfile priorPlug)
                    {
                        for (int i = 0; i < 10; i++)
                        {
                            await Task.Delay(400);
                            var ask = Task.Run(() => VpnService.ReadVpnState(priorPlug));
                            if (await Task.WhenAny(ask, Task.Delay(1500)) == ask &&
                                ask.Result == VpnManagementConnectionStatus.Disconnected)
                            {
                                break;
                            }
                        }
                    }

                    // Ждём завершения 400 мс отсрочки TearDownAndExit в фоновом процессе
                    await Task.Delay(700);
                }

                AppLog.W("  настройки записаны, запуск туннеля");
                _vpnService.WriteSettings(_selectedProfile);
                _pendingProfileChange = false;

                var st = await _vpnService.ConnectProfileAsync(mine);
                AppLog.W("  система вернула на подключение профиля: " + st);

                if (st != VpnManagementErrorStatus.Ok && st != VpnManagementErrorStatus.AlreadyConnected)
                {
                    await Task.Delay(600);
                    var postState = await _vpnService.CheckStatusAsync();
                    if (postState == VpnManagementConnectionStatus.Connected)
                    {
                        AppLog.W("  туннель фактически поднялся несмотря на статус " + st);
                        st = VpnManagementErrorStatus.Ok;
                    }
                    else
                    {
                        // Если RasMan ещё держал остатки прошлой сессии (ошибка Other после дисконнекта),
                        // делаем принудительный сброс состояния профиля и повторный ConnectProfileAsync.
                        AppLog.W($"  статус {st} — выполняю принудительный сброс сессии RasMan и повторное подключение...");
                        StatusText = "Сброс сессии и повтор...";
                        await _vpnService.DisconnectProfileAsync(mine);
                        await Task.Delay(1100);
                        _vpnService.InvalidateProfileCache();
                        mine = await _vpnService.FindOwnProfileAsync() ?? mine;
                        _vpnService.WriteSettings(_selectedProfile);
                        st = await _vpnService.ConnectProfileAsync(mine);
                        AppLog.W("  повторный ConnectProfileAsync вернул: " + st);

                        if (st != VpnManagementErrorStatus.Ok && st != VpnManagementErrorStatus.AlreadyConnected)
                        {
                            await Task.Delay(600);
                            if (await _vpnService.CheckStatusAsync() == VpnManagementConnectionStatus.Connected)
                            {
                                st = VpnManagementErrorStatus.Ok;
                            }
                        }
                    }
                }

                if (st == VpnManagementErrorStatus.Ok || st == VpnManagementErrorStatus.AlreadyConnected)
                {
                    IsConnected = true;
                    ActiveTime = TimeSpan.Zero;
                    StatusText = $"Подключен: {_selectedProfile.Name}";
                    UpdateLiveTileConnected(_selectedProfile.Name);
                }
                else
                {
                    int profileCount = await _vpnService.CountMatchingProfilesAsync();
                    AppLog.W($"  не удалось подключить ({st}), профилей в системе: {profileCount}");
                    StatusText = $"Ошибка подключения ({st})";

                    if (RequestConfirmDialog != null)
                    {
                        string title = profileCount > 1 ? "Дубликаты VPN-профиля" : "Ошибка подключения";
                        string msg = profileCount > 1
                            ? $"В системе обнаружено несколько профилей ({profileCount} шт.), из-за чего служба VPN вернула статус: {st}.\n\nУдалите лишний профиль в параметрах VPN, оставив только один."
                            : $"Система вернула статус: {st}.\n\nОткрыть параметры VPN для проверки или ручного запуска профиля?";

                        bool openSettings = await RequestConfirmDialog(title, msg, "Открыть параметры", "Закрыть");
                        if (openSettings)
                        {
                            RequestNavigateToVpnSettings?.Invoke();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"  Исключение при подключении: {ex.Message}");
                StatusText = "Ошибка запуска VPN: " + ex.Message;
            }
            finally
            {
                IsBusy = false;
            }
        }

        public async Task DisconnectAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            StatusText = "Отключение...";
            AppLog.Section("ОТКЛЮЧЕНИЕ");
            try
            {
                var mine = await _vpnService.FindOwnProfileAsync();
                if (mine != null)
                {
                    await _vpnService.DisconnectProfileAsync(mine);
                }
                else
                {
                    await _vpnService.ForceDisconnectActiveProfilesAsync();
                }

                bool released = false;
                for (int i = 0; !released && i < 12; i++)
                {
                    await Task.Delay(500);
                    if (mine is VpnPlugInProfile plug)
                    {
                        var ask = Task.Run(() => VpnService.ReadVpnState(plug));
                        if (await Task.WhenAny(ask, Task.Delay(2000)) == ask)
                        {
                            released = ask.Result != VpnManagementConnectionStatus.Connected;
                        }
                    }
                    else
                    {
                        released = !VpnService.IsVpnInterfaceActive();
                    }
                    StatusText = $"Отключение... ({(i + 1) / 2 + 1} с)";
                }

                if (released)
                {
                    // Даём фоновому процессу (TearDownAndExit = 400 мс) спокойно освободить все deferral,
                    // чтобы мгновенное повторное нажатие «Подключить» не попало в умирающую задачу.
                    await Task.Delay(700);
                }

                IsConnected = false;
                ActiveTime = TimeSpan.Zero;
                VlessVpnTask.LiveTile.ShowDisconnected();

                if (_pendingProfileChange && _selectedProfile != null)
                {
                    _vpnService.WriteSettings(_selectedProfile);
                    _pendingProfileChange = false;
                    StatusText = $"Отключено. Применён «{_selectedProfile.Name}».";
                }
                else
                {
                    StatusText = released ? "Отключено" : "Система не ответила вовремя. Проверьте настройки VPN.";
                }

                if (!released)
                {
                    AppLog.W("  система за 6 секунд туннель не отпустила");
                    if (RequestConfirmDialog != null)
                    {
                        bool open = await RequestConfirmDialog("Отключение VPN",
                            "Туннель не ответил на отключение. Открыть параметры сети?",
                            "Открыть настройки", "Закрыть");
                        if (open) RequestNavigateToVpnSettings?.Invoke();
                    }
                }
                else
                {
                    AppLog.W("  туннель успешно отключен");
                }
            }
            finally
            {
                IsBusy = false;
            }
        }

        // ==================== ПЕРИОДИЧЕСКИЙ ОПРОС СТАТУСА ====================

        public async Task PollVpnStatusAsync()
        {
            try
            {
                var mine = await _vpnService.FindOwnProfileAsync();
                if (mine is VpnPlugInProfile plug)
                {
                    var ask = Task.Run(() => VpnService.ReadVpnState(plug));
                    if (await Task.WhenAny(ask, Task.Delay(3000)) != ask) return;

                    var status = ask.Result;
                    bool connected = (status == VpnManagementConnectionStatus.Connected);
                    RefreshTransportWarning(connected);

                    if (connected)
                    {
                        if (!IsConnected)
                        {
                            IsConnected = true;
                            ActiveTime = TimeSpan.Zero;
                            string connName = _selectedProfile != null ? _selectedProfile.Name : mine.ProfileName;
                            StatusText = $"Подключен (глобально): {connName}";
                            UpdateLiveTileConnected(connName);
                        }
                    }
                    else if (status == VpnManagementConnectionStatus.Connecting)
                    {
                        StatusText = "Подключение в системе...";
                    }
                    else if (status == VpnManagementConnectionStatus.Disconnecting)
                    {
                        StatusText = "Отключение в системе...";
                    }
                    else
                    {
                        VlessVpnTask.LiveTile.ShowDisconnected();
                        if (IsConnected)
                        {
                            IsConnected = false;
                            ActiveTime = TimeSpan.Zero;
                            if (_pendingProfileChange && _selectedProfile != null)
                            {
                                _vpnService.WriteSettings(_selectedProfile);
                                _pendingProfileChange = false;
                                StatusText = $"Отключено. Применён «{_selectedProfile.Name}».";
                            }
                            else
                            {
                                StatusText = "Отключено";
                            }
                        }
                    }
                }
                else
                {
                    VlessVpnTask.LiveTile.ShowDisconnected();
                    RefreshTransportWarning(false);
                    if (IsConnected)
                    {
                        _vpnService.InvalidateProfileCache();
                        IsConnected = false;
                        ActiveTime = TimeSpan.Zero;
                        if (_pendingProfileChange && _selectedProfile != null)
                        {
                            _vpnService.WriteSettings(_selectedProfile);
                            _pendingProfileChange = false;
                            StatusText = $"Отключено. Применён «{_selectedProfile.Name}».";
                        }
                        else
                        {
                            StatusText = "Отключено";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[STATUS CHECK FAIL] {ex.Message}");
            }
        }

        public void IncrementTimer()
        {
            if (IsConnected)
            {
                ActiveTime = ActiveTime.Add(TimeSpan.FromSeconds(1));
            }
        }

        private void RefreshTransportWarning(bool connected)
        {
            try
            {
                if (!connected)
                {
                    TransportWarnText = "";
                    return;
                }

                string why = VlessVpnTask.NetDiag.ReadLastError();
                TransportWarnText = string.IsNullOrEmpty(why) ? "" : "Внимание: " + why;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TRANSPORT WARN] {ex.Message}");
            }
        }

        private void UpdateLiveTileConnected(string connName)
        {
            try
            {
                var p = _selectedProfile;
                string details = "";
                if (p != null)
                {
                    string proto = p.IsShadowsocks ? "shadowsocks"
                                 : p.IsAmneziaWg ? "amneziawg"
                                 : "vless";
                    details = string.IsNullOrEmpty(p.Address) ? proto : $"{proto} · {p.Address}";
                }
                VlessVpnTask.LiveTile.ShowConnected(connName, details);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TILE] {ex.Message}");
            }
        }

        // ==================== ПРОВЕРКА ПОДКЛЮЧЕНИЯ (ПИНГ) ====================

        public async Task CheckConnectionAsync()
        {
            if (!IsConnected)
            {
                if (SelectedProfile != null)
                {
                    StatusText = $"Проверка {SelectedProfile.Name}...";
                    await PingService.PingAsync(SelectedProfile);
                    string ping = SelectedProfile.CleanPingText ?? "";
                    StatusText = $"{SelectedProfile.Name}: {ping}";
                }
                else
                {
                    StatusText = "Выберите сервер для проверки";
                }
                return;
            }

            StatusText = "Проверка связности...";
            var sw = Stopwatch.StartNew();

            try
            {
                using (var client = new Windows.Web.Http.HttpClient())
                {
                    var req = new Windows.Web.Http.HttpRequestMessage(
                        Windows.Web.Http.HttpMethod.Get,
                        new Uri("https://cp.cloudflare.com/generate_204")
                    );
                    req.Headers.Connection.Add(new Windows.Web.Http.Headers.HttpConnectionOptionHeaderValue("close"));

                    using (var cts = new System.Threading.CancellationTokenSource(4000))
                    {
                        var resp = await client.SendRequestAsync(
                            req,
                            Windows.Web.Http.HttpCompletionOption.ResponseHeadersRead
                        ).AsTask(cts.Token);

                        sw.Stop();
                        if (resp.IsSuccessStatusCode)
                        {
                            StatusText = $"Связь в норме: {sw.ElapsedMilliseconds} мс";
                        }
                        else
                        {
                            StatusText = $"HTTP {(int)resp.StatusCode}: {sw.ElapsedMilliseconds} мс";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                string msg = ex.Message ?? "";
                if (msg.Length > 40) msg = msg.Substring(0, 40) + "...";
                StatusText = $"Нет связи ({sw.ElapsedMilliseconds} мс): {msg}";
            }
        }

        // ==================== ОПЕРАЦИИ С ПРОФИЛЯМИ И ПОДПИСКАМИ ====================

        public async Task DeleteProfileAsync(VlessProfile profile)
        {
            if (profile == null) return;
            _allProfiles.Remove(profile);
            if (_selectedProfile == profile)
            {
                _selectedProfile = null;
                OnPropertyChanged(nameof(SelectedProfile));
            }
            UpdateGroupedUI();
            await SaveProfilesAsync();
            StatusText = "Профиль удален";
        }

        public async Task PingProfileAsync(VlessProfile profile)
        {
            if (profile == null) return;
            await PingService.PingAsync(profile);
        }

        public async Task PingGroupAsync(ProfileGroup group)
        {
            if (group == null || group.Count == 0) return;

            _groupPingCts?.Cancel();
            _groupPingCts = new CancellationTokenSource();
            var ct = _groupPingCts.Token;

            int total = group.Count;
            int done = 0;
            int active = 0;
            int failed = 0;

            StatusText = $"Проверка группы: 0/{total}...";

            var semaphore = new SemaphoreSlim(4, 4);
            var tasks = group.Select(async profile =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    if (ct.IsCancellationRequested) return;
                    await PingService.PingAsync(profile, ct);

                    int currentDone = Interlocked.Increment(ref done);
                    string ping = profile.CleanPingText ?? "";
                    if (ping.EndsWith("мс"))
                        Interlocked.Increment(ref active);
                    else if (ping.Contains("Таймаут") || ping.Contains("Ошибка"))
                        Interlocked.Increment(ref failed);

                    if (currentDone % 2 == 0 || currentDone == total)
                    {
                        StatusText = $"Проверка: {currentDone}/{total} ({active} доступно)...";
                    }
                }
                catch (OperationCanceledException) { }
                finally
                {
                    semaphore.Release();
                }
            }).ToList();

            try
            {
                await Task.WhenAll(tasks);
                if (!ct.IsCancellationRequested)
                {
                    SortGroupProfiles(group);
                    StatusText = $"Проверено: {active} доступно, {failed} недоступно.";
                }
            }
            catch (OperationCanceledException)
            {
                StatusText = "Проверка отменена.";
            }
        }

        public void SortGroupProfiles(ProfileGroup group)
        {
            if (group == null || group.Count <= 1) return;

            var sorted = group.OrderBy(p =>
            {
                string text = p.CleanPingText ?? "";
                int space = text.IndexOf(' ');
                if (space > 0 && int.TryParse(text.Substring(0, space), out int ms))
                    return ms;
                if (text.Contains("Не выдан"))
                    return 99998;
                return 99999;
            }).ToList();

            group.Clear();
            foreach (var p in sorted) group.Add(p);
        }

        public async Task DeleteGroupAsync(ProfileGroup group)
        {
            if (group == null) return;

            int count = _allProfiles.Count(p => p.SubscriptionGroup == group.Key);
            if (RequestConfirmDialog != null)
            {
                bool ok = await RequestConfirmDialog("Удалить подписку?",
                    $"«{group.Title}» и все серверы из неё ({count} шт.) будут удалены. Отменить это будет нельзя.",
                    "Удалить", "Отмена");
                if (!ok) return;
            }

            _allProfiles.RemoveAll(p => p.SubscriptionGroup == group.Key);
            UpdateGroupedUI();
            await SaveProfilesAsync();
            StatusText = "Подписка удалена.";
            _selectedProfile = null;
            OnPropertyChanged(nameof(SelectedProfile));
        }

        public async Task RenameGroupAsync(ProfileGroup group, string newName)
        {
            if (group == null) return;
            string name = (newName ?? "").Trim();
            foreach (var p in _allProfiles.Where(p => p.SubscriptionGroup == group.Key))
            {
                p.GroupTitle = name;
                p.GroupTitleCustom = !string.IsNullOrEmpty(name);
            }

            UpdateGroupedUI();
            await SaveProfilesAsync();
            StatusText = string.IsNullOrEmpty(name) ? "Имя подписки сброшено." : $"Подписка переименована: {name}";
        }

        public static bool IsRefreshableGroup(string group)
        {
            return !string.IsNullOrEmpty(group) &&
                   (group.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase));
        }

        public static bool IsAutoRefreshableGroup(string group)
        {
            return IsRefreshableGroup(group) &&
                   !group.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase);
        }

        public async Task ProcessAndAddImportTextAsync(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return;

            StatusText = "Загрузка/Парсинг...";
            IsBusy = true;

            try
            {
                var newProfiles = await VlessProfile.ProcessInputAsync(text);

                if (newProfiles.Count > 0)
                {
                    var incomingSubscriptions = newProfiles
                        .Select(p => p.SubscriptionGroup)
                        .Distinct()
                        .Where(IsRefreshableGroup)
                        .ToList();

                    foreach (var subUrl in incomingSubscriptions)
                    {
                        _allProfiles.RemoveAll(p => string.Equals(p.SubscriptionGroup, subUrl, StringComparison.OrdinalIgnoreCase));
                    }

                    PopulateMetadata(newProfiles, text);
                    foreach (var g in incomingSubscriptions) ExpandAmneziaRows(newProfiles, g);
                    _allProfiles.AddRange(newProfiles);

                    UpdateGroupedUI();
                    await SaveProfilesAsync();
                    AppLog.W($"[ИМПОРТ] Добавлено {newProfiles.Count} шт., групп: " +
                             string.Join(", ", newProfiles.Select(p => p.SubscriptionGroup).Distinct()));
                    StatusText = $"Импортировано {newProfiles.Count} серверов";
                    if (RequestImportReportDialog != null) await RequestImportReportDialog(newProfiles.Count);
                }
                else
                {
                    StatusText = "В импортированных данных не найдено профилей";
                    if (RequestImportReportDialog != null) await RequestImportReportDialog(0);
                }
            }
            catch (AmneziaUnsupportedConfigException ex)
            {
                StatusText = "Конфиг получен, но не разобран.";
                if (RequestUnsupportedConfigDialog != null) await RequestUnsupportedConfigDialog(ex);
            }
            catch (Exception ex)
            {
                StatusText = "Ошибка импорта: " + ex.Message;
                if (AmneziaLink.IsAmneziaLink(text) && RequestAmneziaErrorDialog != null)
                {
                    await RequestAmneziaErrorDialog(ex);
                }
            }
            finally
            {
                IsBusy = false;
            }
        }

        private static void PopulateMetadata(List<VlessProfile> profiles, string url)
        {
            foreach (var p in profiles)
            {
                p.LastUpdated = DateTime.Now;
            }
        }

        private static void ExpandAmneziaRows(List<VlessProfile> profiles, string groupName)
        {
            var issued = profiles.FirstOrDefault(p => p.IsAmneziaRow && !p.AmneziaNotIssued);
            if (issued == null) return;
            profiles.AddRange(AmneziaApi.BuildCountryRows(issued, groupName));
        }

        public async Task IssueAmneziaRowAsync(VlessProfile row)
        {
            var sub = AmneziaLink.TryGetApiSubscription(row.SubscriptionGroup);
            if (sub == null)
            {
                StatusText = "Не удалось прочитать ключ подписки из ссылки.";
                return;
            }
            sub.ServerCountryCode = row.AmneziaCountryCode;
            sub.ServiceProtocol = row.AmneziaProtocol;

            AmneziaApi.ClearLog();
            AmneziaApi.Log($"Запрос конфига для строки списка: {row.AmneziaCountryCode}/{row.AmneziaCountryName}, протокол {row.AmneziaProtocol}.");

            string was = row.CleanPingText;
            row.CleanPingText = "Запрашиваем...";
            try
            {
                var fetched = await AmneziaApi.FetchAsync(sub, row.SubscriptionGroup);
                var issued = fetched.FirstOrDefault();
                if (issued == null)
                {
                    row.CleanPingText = was;
                    StatusText = "Шлюз не выдал конфиг для этой страны.";
                    return;
                }

                int idx = _allProfiles.IndexOf(row);
                issued.GroupTitle = row.GroupTitle;
                issued.GroupTitleCustom = row.GroupTitleCustom;
                if (idx >= 0) _allProfiles[idx] = issued; else _allProfiles.Add(issued);

                foreach (var p in _allProfiles.Where(p => p.SubscriptionGroup == row.SubscriptionGroup))
                {
                    p.AmneziaCountries = issued.AmneziaCountries;
                    p.AmneziaInfo = issued.AmneziaInfo;
                }

                UpdateGroupedUI();
                await SaveProfilesAsync();

                StatusText = $"Проверяем {issued.Address}...";
                await PingService.PingAsync(issued);

                string ping = issued.CleanPingText ?? "";
                bool pingFailed = ping.StartsWith("Таймаут") || ping.StartsWith("Ошибка");
                SelectProfile(issued);
                if (pingFailed)
                {
                    StatusText = $"Конфиг получен: {issued.Name}. Задержку измерить не удалось.";
                    AmneziaApi.Log($"  выданный узел {issued.Address}:{issued.Port} не ответил на пробу ({ping}). " +
                                   "Конфиг сохранён, подключение возможно.");
                }
                else
                {
                    StatusText = $"Конфиг получен: {issued.Name} ({ping})";
                }
            }
            catch (AmneziaUnsupportedConfigException ex)
            {
                row.CleanPingText = was;
                if (RequestUnsupportedConfigDialog != null) await RequestUnsupportedConfigDialog(ex);
            }
            catch (Exception ex)
            {
                row.CleanPingText = was;
                StatusText = "Не удалось получить конфиг.";
                if (RequestAmneziaErrorDialog != null) await RequestAmneziaErrorDialog(ex);
            }
        }

        public async Task PerformSubscriptionUpdateAsync(string url)
        {
            if (!IsRefreshableGroup(url)) return;

            StatusText = "Обновление...";
            try
            {
                var newProfiles = await VlessProfile.ProcessInputAsync(url);
                if (newProfiles.Count > 0)
                {
                    var renamed = _allProfiles.FirstOrDefault(p => p.SubscriptionGroup == url && p.GroupTitleCustom);
                    string customTitle = renamed != null ? renamed.GroupTitle : null;

                    string prevSelectedName = _selectedProfile?.Name;
                    string prevSelectedUuid = _selectedProfile?.Uuid;
                    string prevSelectedAddr = _selectedProfile?.Address;
                    int prevSelectedPort = _selectedProfile != null ? _selectedProfile.Port : 0;

                    _allProfiles.RemoveAll(p => p.SubscriptionGroup == url);

                    PopulateMetadata(newProfiles, url);
                    if (!string.IsNullOrEmpty(customTitle))
                    {
                        foreach (var p in newProfiles) { p.GroupTitle = customTitle; p.GroupTitleCustom = true; }
                    }
                    ExpandAmneziaRows(newProfiles, url);
                    _allProfiles.AddRange(newProfiles);

                    if (!string.IsNullOrEmpty(prevSelectedAddr))
                    {
                        var restored = _allProfiles.FirstOrDefault(p =>
                            (prevSelectedUuid != null && p.Uuid == prevSelectedUuid && p.Address == prevSelectedAddr && p.Port == prevSelectedPort) ||
                            (p.Name == prevSelectedName && p.Address == prevSelectedAddr));
                        if (restored != null)
                        {
                            SelectProfile(restored);
                        }
                    }

                    UpdateGroupedUI();
                    await SaveProfilesAsync();
                    StatusText = $"Подписка успешно обновлена! Найдено {newProfiles.Count} серверов.";
                }
                else
                {
                    StatusText = "Подписка пуста.";
                }
            }
            catch (Exception ex)
            {
                StatusText = "Ошибка обновления: " + ex.Message;
            }
        }

        public async Task CheckAndAutoUpdateSubscriptionsAsync()
        {
            var subscriptionsToUpdate = _allProfiles
                .Where(p => IsAutoRefreshableGroup(p.SubscriptionGroup))
                .GroupBy(p => p.SubscriptionGroup)
                .Where(g => (DateTime.Now - g.First().LastUpdated).TotalHours >= 1)
                .Select(g => g.Key)
                .ToList();

            if (subscriptionsToUpdate.Count > 0)
            {
                Debug.WriteLine($"[AUTO-UPDATE] Запуск автообновления: {subscriptionsToUpdate.Count}");
                foreach (var url in subscriptionsToUpdate)
                {
                    await PerformSubscriptionUpdateAsync(url);
                }
            }
        }
    }
}
