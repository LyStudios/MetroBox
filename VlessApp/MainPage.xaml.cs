using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.UI;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using VlessApp.Services;
using VlessApp.ViewModels;

namespace VlessApp
{
    public sealed partial class MainPage : Page
    {
        public static bool IsRedirectingToSettings = false;

        // Одна кисть на все акцентные элементы вместо шести одинаковых.
        private static readonly Brush AccentBrush = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));
        private static readonly Brush DefaultPowerBrush = new SolidColorBrush(Colors.White);
        private static readonly Brush DefaultRingBrush = new SolidColorBrush(Color.FromArgb(255, 37, 99, 235));
        private static readonly Brush DefaultTextBrush = new SolidColorBrush(Color.FromArgb(255, 156, 163, 175));

        public MainViewModel ViewModel { get; }

        private readonly DispatcherTimer _timer;
        private readonly DispatcherTimer _statusTimer;
        private readonly DispatcherTimer _autoUpdateTimer;
        private bool _isCheckingStatus = false;
        private List<StorageFile> _logFilesToShare;

        public MainPage()
        {
            this.InitializeComponent();

            ViewModel = new MainViewModel();
            this.DataContext = ViewModel;

            IsRedirectingToSettings = false;
            GroupedProfilesCVS.Source = ViewModel.GroupedProfiles;

            ViewModel.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(MainViewModel.StatusText))
                {
                    StatusText.Text = ViewModel.StatusText;
                }
            };

            WireViewModelCallbacks();

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (s, e) =>
            {
                ViewModel.IncrementTimer();
                TimeText.Text = ViewModel.ActiveTimeString;
            };

            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2.5) };
            _statusTimer.Tick += StatusTimer_Tick;
            _statusTimer.Start();

            _autoUpdateTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(5) };
            _autoUpdateTimer.Tick += async (s, e) => await ViewModel.CheckAndAutoUpdateSubscriptionsAsync();
            _autoUpdateTimer.Start();

            Application.Current.Resuming += Current_Resuming;
            Loaded += MainPage_Loaded;
        }

        private void WireViewModelCallbacks()
        {
            ViewModel.RequestConfirmDialog = async (title, content, primary, secondary) =>
            {
                var dlg = new ContentDialog
                {
                    Title = title,
                    Content = content,
                    PrimaryButtonText = primary,
                    SecondaryButtonText = secondary
                };
                var res = await dlg.ShowAsync();
                return res == ContentDialogResult.Primary;
            };

            ViewModel.RequestMessageDialog = async (title, content) =>
            {
                var dlg = new ContentDialog
                {
                    Title = title,
                    Content = content,
                    PrimaryButtonText = "ОК"
                };
                await dlg.ShowAsync();
            };

            ViewModel.RequestImportReportDialog = ShowImportReportAsync;
            ViewModel.RequestAmneziaErrorDialog = ShowAmneziaErrorAsync;
            ViewModel.RequestUnsupportedConfigDialog = ShowUnsupportedConfigAsync;

            ViewModel.RequestNavigateToVpnSettings = async () =>
            {
                IsRedirectingToSettings = true;
                await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-settings:network-vpn"));
            };

            ViewModel.RequestHardReset = HardResetMainPage;
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            await ViewModel.InitializeAsync();
            UpdateVisualConnectionState(ViewModel.IsConnected);
            UpdateHideAllVisibility();
        }

        private void Current_Resuming(object sender, object e)
        {
            System.Diagnostics.Debug.WriteLine("[RESUME] Приложение восстановлено.");
            _isCheckingStatus = false;
            IsRedirectingToSettings = false;
        }

        private async void StatusTimer_Tick(object sender, object e)
        {
            if (_isCheckingStatus) return;
            _isCheckingStatus = true;
            try
            {
                bool wasConnected = ViewModel.IsConnected;
                await ViewModel.PollVpnStatusAsync();
                if (wasConnected != ViewModel.IsConnected)
                {
                    UpdateVisualConnectionState(ViewModel.IsConnected);
                }

                // Обновление состояния плашки предупреждения транспорта
                if (ViewModel.HasTransportWarning)
                {
                    TransportWarnText.Text = ViewModel.TransportWarnText;
                    TransportWarnText.Visibility = Visibility.Visible;
                }
                else
                {
                    TransportWarnText.Visibility = Visibility.Collapsed;
                }

                UpdateHideAllVisibility();
            }
            finally
            {
                _isCheckingStatus = false;
            }
        }

        private void UpdateVisualConnectionState(bool connected)
        {
            if (connected)
            {
                _timer.Start();

                GlowRing1.BorderBrush = AccentBrush;
                GlowRing2.BorderBrush = AccentBrush;
                GlowRing1.Opacity = 0.15;
                GlowRing2.Opacity = 0.35;
                PowerIcon.Foreground = AccentBrush;

                TimeText.Visibility = Visibility.Visible;
                TimeText.Foreground = AccentBrush;
                TimeText.Text = ViewModel.ActiveTimeString;

                ConnectBtnText.Text = "ПОДКЛЮЧЕН";
                ConnectBtnText.Foreground = AccentBrush;
                ConnectBtn.BorderBrush = AccentBrush;
                ConnectBtn.Background = this.Resources["ButtonGlowConnected"] as Brush;
                CheckConnectionText.Text = "Проверить текущее подключение";
            }
            else
            {
                _timer.Stop();

                GlowRing1.BorderBrush = DefaultRingBrush;
                GlowRing2.BorderBrush = DefaultRingBrush;
                GlowRing1.Opacity = 0.10;
                GlowRing2.Opacity = 0.25;
                PowerIcon.Foreground = DefaultPowerBrush;

                TimeText.Visibility = Visibility.Collapsed;

                ConnectBtnText.Text = "ПОДКЛЮЧИТЬ";
                ConnectBtnText.Foreground = DefaultTextBrush;
                ConnectBtn.BorderBrush = DefaultRingBrush;
                ConnectBtn.Background = this.Resources["ButtonGlowDisconnected"] as Brush;
            }
        }

        private void UpdateHideAllVisibility()
        {
            HideAllBtn.Visibility = ViewModel.IsHideAllVisible ? Visibility.Visible : Visibility.Collapsed;
        }

        private void HardResetMainPage()
        {
            System.Diagnostics.Debug.WriteLine("[RESET UI] Сброс визуального состояния...");
            UpdateVisualConnectionState(ViewModel.IsConnected);
            UpdateHideAllVisibility();
        }

        // ==================== ДЕЙСТВИЯ КНОПОК И ЖЕСТОВ ====================

        private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsBusy) return;
            ConnectBtn.IsEnabled = false;
            ConnectBtnText.Text = ViewModel.IsConnected ? "ОТКЛЮЧЕНИЕ..." : "ПОДКЛЮЧЕНИЕ...";
            try
            {
                await ViewModel.ToggleConnectCommand.ExecuteAsync();
            }
            finally
            {
                ConnectBtn.IsEnabled = true;
                UpdateVisualConnectionState(ViewModel.IsConnected);
            }
        }

        private void HideAll_Tapped(object sender, TappedRoutedEventArgs e)
        {
            ViewModel.CollapseAllCommand.Execute(null);
            UpdateHideAllVisibility();
        }

        private void GroupHeader_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.Tag as ProfileGroup;
            if (group != null)
            {
                ViewModel.ToggleGroupExpansion(group);
                UpdateHideAllVisibility();
            }
        }

        private async void CheckConnection_Tapped(object sender, TappedRoutedEventArgs e)
        {
            await ViewModel.CheckConnectionCommand.ExecuteAsync();
        }

        private async void Item_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var profile = grid?.DataContext as VlessProfile;
            if (profile == null) return;

            if (profile.AmneziaNotIssued)
            {
                await ViewModel.IssueAmneziaRowAsync(profile);
                return;
            }

            ViewModel.SelectProfile(profile);
        }

        private void SettingsBtn_Click(object sender, RoutedEventArgs e)
        {
            AboutPageGrid.Visibility = Visibility.Visible;
        }

        private void AboutBackBtn_Click(object sender, RoutedEventArgs e)
        {
            AboutPageGrid.Visibility = Visibility.Collapsed;
        }

        // ==================== ИМПОРТ ИЗ БУФЕРА И QR ====================

        private async void ImportFromClipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dataPackageView = Clipboard.GetContent();
                if (dataPackageView.Contains(StandardDataFormats.Text))
                {
                    string text = await dataPackageView.GetTextAsync();
                    await ViewModel.ProcessAndAddImportTextAsync(text);
                }
                else
                {
                    StatusText.Text = "Буфер обмена пуст";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка импорта: " + ex.Message;
            }
        }

        private async void ScanQrCode_Click(object sender, RoutedEventArgs e)
        {
            var selectSourceDialog = new ContentDialog
            {
                Title = "Сканирование QR-кода",
                Content = "Выберите источник изображения с QR-кодом:",
                PrimaryButtonText = "Камера",
                SecondaryButtonText = "Галерея"
            };

            var choice = await selectSourceDialog.ShowAsync();
            StorageFile file = null;

            try
            {
                if (choice == ContentDialogResult.Primary)
                {
                    var captureUI = new Windows.Media.Capture.CameraCaptureUI();
                    captureUI.PhotoSettings.Format = Windows.Media.Capture.CameraCaptureUIPhotoFormat.Jpeg;
                    file = await captureUI.CaptureFileAsync(Windows.Media.Capture.CameraCaptureUIMode.Photo);
                }
                else if (choice == ContentDialogResult.Secondary)
                {
                    var picker = new Windows.Storage.Pickers.FileOpenPicker();
                    picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.PicturesLibrary;
                    picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.Thumbnail;
                    picker.FileTypeFilter.Add(".jpg");
                    picker.FileTypeFilter.Add(".jpeg");
                    picker.FileTypeFilter.Add(".png");
                    picker.FileTypeFilter.Add(".bmp");

                    file = await picker.PickSingleFileAsync();
                }

                if (file == null)
                {
                    StatusText.Text = "Сканирование отменено";
                    return;
                }

                StatusText.Text = "Обработка и распознавание (многопроходный анализ)...";
                string qrResult = null;

                using (var stream = await file.OpenAsync(FileAccessMode.Read))
                {
                    qrResult = await QrDecoder.DecodeAsync(stream, s => StatusText.Text = s);
                }

                if (!string.IsNullOrEmpty(qrResult))
                {
                    StatusText.Text = "Код успешно распознан!";
                    await ViewModel.ProcessAndAddImportTextAsync(qrResult);
                }
                else
                {
                    StatusText.Text = "Не удалось распознать QR-код.";
                    var failDialog = new ContentDialog
                    {
                        Title = "Ошибка распознавания",
                        Content = "Локальный декодер не смог распознать QR-код даже после многопроходного анализа.\n\n" +
                                  "Убедитесь, что QR-код находится в фокусе, полностью попадает в кадр и не перекрыт бликами от освещения.",
                        PrimaryButtonText = "ОК"
                    };
                    await failDialog.ShowAsync();
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка сканирования: " + ex.Message;
            }
        }

        // ==================== ДИАЛОГИ ИМПОРТА И ОШИБОК ====================

        private async Task ShowImportReportAsync(int added)
        {
            try
            {
                var rep = VlessProfile.LastImport;
                if (rep == null) return;
                if (rep.Skipped.Count == 0 && rep.Warnings.Count == 0) return;

                var sb = new StringBuilder();
                if (added > 0)
                {
                    sb.Append("Успешно добавлено серверов: ").Append(added).AppendLine(".");
                }

                if (rep.Skipped.Count > 0)
                {
                    if (sb.Length > 0) sb.AppendLine();
                    sb.Append("Пропущено неподдерживаемых строк: ").Append(rep.Skipped.Count)
                      .Append(" (").Append(rep.SkippedSummary()).AppendLine(")");
                    sb.AppendLine("Эти протоколы приложением не поддерживаются.");
                }

                if (rep.Warnings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("Импортированы, но не подключатся:");
                    int shown = 0;
                    foreach (var w in rep.Warnings)
                    {
                        if (shown++ == 6) { sb.AppendLine("  … и ещё " + (rep.Warnings.Count - 6)); break; }
                        sb.Append("  • ").AppendLine(w);
                    }
                }

                sb.AppendLine();
                sb.Append("Подробности — в файле ").Append(AppLog.LogFileName).Append('.');

                var dlg = new ContentDialog
                {
                    Title = "Импортировано не всё",
                    Content = sb.ToString(),
                    PrimaryButtonText = "ОК"
                };
                await dlg.ShowAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[IMPORT REPORT] {ex.Message}");
            }
        }

        private async Task ShowAmneziaErrorAsync(Exception ex)
        {
            string log = AmneziaApi.GetLog();

            var logBox = new TextBox
            {
                Text = log,
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.NoWrap,
                Height = 260,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10
            };

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = ex.Message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(new TextBlock
            {
                Text = "Лог обмена скопирован в буфер обмена.",
                TextWrapping = TextWrapping.Wrap,
                FontSize = 11,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(logBox);

            try
            {
                var data = new DataPackage();
                data.SetText(log);
                Clipboard.SetContent(data);
            }
            catch { }

            await new ContentDialog
            {
                Title = "Ошибка Amnezia API",
                Content = panel,
                PrimaryButtonText = "Понятно"
            }.ShowAsync();
        }

        private async Task ShowUnsupportedConfigAsync(AmneziaApi.UnsupportedConfigException ex)
        {
            var text = new TextBox
            {
                Text = ex.Dump,
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.NoWrap,
                Height = 300,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11
            };

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = ex.Message + "\n\nСтруктура ответа скопирована в буфер обмена — ключи и адреса из неё убраны.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(text);

            try
            {
                var data = new DataPackage();
                data.SetText(ex.Dump);
                Clipboard.SetContent(data);
            }
            catch { }

            await new ContentDialog
            {
                Title = "Протокол пока не поддержан",
                Content = panel,
                PrimaryButtonText = "Понятно"
            }.ShowAsync();
        }

        // ==================== ЖЕСТЫ SWIPE И ДЕЙСТВИЯ СТРОКИ ====================

        private void ContentGrid_Loaded(object sender, RoutedEventArgs e)
        {
            var grid = sender as Grid;
            if (grid != null && grid.RenderTransform is TranslateTransform tt)
            {
                tt.X = 0;
            }
        }

        private void Item_ManipulationDelta(object sender, ManipulationDeltaRoutedEventArgs e)
        {
            var grid = sender as Grid;
            if (grid == null) return;
            var tt = grid.RenderTransform as TranslateTransform;
            if (tt == null) return;

            double newX = tt.X + e.Delta.Translation.X;
            if (newX > 120) newX = 120;
            if (newX < -60) newX = -60;
            tt.X = newX;
        }

        private void Item_ManipulationCompleted(object sender, ManipulationCompletedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            if (grid == null) return;
            var tt = grid.RenderTransform as TranslateTransform;
            if (tt == null) return;

            if (tt.X > 50) tt.X = 120;
            else if (tt.X < -25) tt.X = -60;
            else
            {
                tt.X = 0;
                var profile = grid.DataContext as VlessProfile;
                if (profile != null) profile.IsShareOpen = false;
            }
        }

        private void CloseSwipePanel(DependencyObject btn)
        {
            var parentGrid = FindParent<Grid>(btn);
            while (parentGrid != null && parentGrid.Name != "ContentGrid")
            {
                parentGrid = FindParent<Grid>(parentGrid);
            }
            if (parentGrid != null && parentGrid.RenderTransform is TranslateTransform tt)
            {
                tt.X = 0;
            }
        }

        private T FindParent<T>(DependencyObject child) where T : DependencyObject
        {
            DependencyObject parent = VisualTreeHelper.GetParent(child);
            while (parent != null && !(parent is T))
            {
                parent = VisualTreeHelper.GetParent(parent);
            }
            return parent as T;
        }

        private async void SwipePing_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.Tag as VlessProfile;
            if (profile != null)
            {
                CloseSwipePanel(button);
                await ViewModel.PingProfileAsync(profile);
            }
        }

        private void SwipeShare_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.Tag as VlessProfile;
            if (profile != null)
            {
                profile.IsShareOpen = true;
            }
        }

        private async void SwipeDelete_Click(object sender, TappedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var profile = grid?.Tag as VlessProfile;
            if (profile != null)
            {
                await ViewModel.DeleteProfileAsync(profile);
            }
        }

        private void ShareUrl_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string url = ShareLinkBuilder.BuildUrl(profile);
                var dp = new DataPackage();
                dp.SetText(url);
                Clipboard.SetContent(dp);
                StatusText.Text = "Ссылка скопирована в буфер!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        private void ShareQr_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string url = ShareLinkBuilder.BuildUrl(profile);
                var dp = new DataPackage();
                dp.SetText(url);
                Clipboard.SetContent(dp);
                StatusText.Text = "QR-ссылка скопирована!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        private void ShareJson_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string json = ShareLinkBuilder.BuildJson(profile);
                var dp = new DataPackage();
                dp.SetText(json);
                Clipboard.SetContent(dp);
                StatusText.Text = "JSON скопирован в буфер!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        // ==================== ОПЕРАЦИИ С ГРУППАМИ / ПОДПИСКАМИ ====================

        private async void UpdateSubscription_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                await ViewModel.PerformSubscriptionUpdateAsync(group.Key);
            }
        }

        private async void PingGroup_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                await ViewModel.PingGroupAsync(group);
            }
        }

        private async void RenameSubscription_Click(object sender, RoutedEventArgs e)
        {
            var group = (sender as Button)?.DataContext as ProfileGroup;
            if (group == null) return;

            var input = new TextBox
            {
                Text = group.Title,
                PlaceholderText = "Имя подписки",
                AcceptsReturn = false,
                SelectionStart = 0,
                SelectionLength = group.Title != null ? group.Title.Length : 0
            };

            var dialog = new ContentDialog
            {
                Title = "Переименовать подписку",
                Content = input,
                PrimaryButtonText = "Сохранить",
                SecondaryButtonText = "Отмена"
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
            await ViewModel.RenameGroupAsync(group, input.Text);
        }

        private async void DeleteSubscription_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as Button;
            var group = menuItem?.DataContext as ProfileGroup;
            if (group != null)
            {
                await ViewModel.DeleteGroupAsync(group);
            }
        }

        private async void InfoLink_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.DataContext as ProfileGroup;
            if (group != null && !string.IsNullOrEmpty(group.InfoUrl))
            {
                await Windows.System.Launcher.LaunchUriAsync(new Uri(group.InfoUrl));
            }
        }

        private async void TelegramLink_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.DataContext as ProfileGroup;
            if (group != null && !string.IsNullOrEmpty(group.TelegramUrl))
            {
                await Windows.System.Launcher.LaunchUriAsync(new Uri(group.TelegramUrl));
            }
        }

        private async void PickAmneziaCountry_Click(object sender, RoutedEventArgs e)
        {
            var group = (sender as Button)?.DataContext as ProfileGroup;
            if (group == null) return;

            var current = ViewModel.AllProfiles.FirstOrDefault(p => p.SubscriptionGroup == group.Key);
            if (current == null) return;

            var countries = AmneziaApi.DeserializeCountries(current.AmneziaCountries);
            if (countries.Count == 0)
            {
                StatusText.Text = "Шлюз не прислал список стран — обновите подписку.";
                await new ContentDialog
                {
                    Title = "Список стран пуст",
                    Content = "Шлюз Amnezia не прислал available_countries. Нажмите «обновить» у подписки и попробуйте снова.",
                    PrimaryButtonText = "Понятно"
                }.ShowAsync();
                return;
            }

            var list = new ListView
            {
                SelectionMode = ListViewSelectionMode.Single,
                ItemsSource = countries,
                Height = 320
            };
            var preselected = countries.FirstOrDefault(c =>
                string.Equals(c.Code, current.AmneziaCountryCode, StringComparison.OrdinalIgnoreCase));
            if (preselected != null) list.SelectedItem = preselected;

            var dialog = new ContentDialog
            {
                Title = "Страна подключения",
                Content = list,
                PrimaryButtonText = "Переключить",
                SecondaryButtonText = "Отмена"
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            var chosen = list.SelectedItem as AmneziaApi.Country;
            if (chosen == null) return;

            var sub = AmneziaLink.TryGetApiSubscription(group.Key);
            if (sub == null)
            {
                StatusText.Text = "Не удалось прочитать ключ подписки из ссылки.";
                return;
            }

            sub.ServerCountryCode = chosen.Code;

            if (chosen.Protocols.Count > 1)
            {
                var protoList = new ListView
                {
                    SelectionMode = ListViewSelectionMode.Single,
                    ItemsSource = chosen.Protocols.Select(p => p.ToUpperInvariant()).ToList()
                };
                string currentProto = (current.AmneziaProtocol ?? "").ToUpperInvariant();
                var preProto = chosen.Protocols.Select(p => p.ToUpperInvariant())
                                               .FirstOrDefault(p => p == currentProto);
                protoList.SelectedItem = preProto ?? chosen.Protocols[0].ToUpperInvariant();

                var protoDialog = new ContentDialog
                {
                    Title = $"Протокол · {chosen.Name}",
                    Content = protoList,
                    PrimaryButtonText = "Выбрать",
                    SecondaryButtonText = "Отмена"
                };
                if (await protoDialog.ShowAsync() != ContentDialogResult.Primary) return;

                string pickedProto = protoList.SelectedItem as string;
                sub.ServiceProtocol = chosen.Protocols.FirstOrDefault(p =>
                    string.Equals(p, pickedProto, StringComparison.OrdinalIgnoreCase)) ?? chosen.Protocols[0];
            }
            else if (chosen.Protocols.Count == 1)
            {
                sub.ServiceProtocol = chosen.Protocols[0];
            }

            if (string.Equals(chosen.Code, current.AmneziaCountryCode, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(sub.ServiceProtocol, current.AmneziaProtocol, StringComparison.OrdinalIgnoreCase))
            {
                StatusText.Text = "Эта страна и протокол уже выбраны.";
                return;
            }

            AmneziaApi.ClearLog();
            AmneziaApi.Log($"Пользователь выбрал: страна {chosen.Code}/{chosen.Name}, запрашиваем протокол {sub.ServiceProtocol}.");

            StatusText.Text = $"Переключаем на {chosen.Name} ({sub.ServiceProtocol})...";
            try
            {
                var fetched = await AmneziaApi.FetchAsync(sub, group.Key);
                if (fetched.Count == 0)
                {
                    StatusText.Text = "Шлюз не выдал конфиг для этой страны.";
                    return;
                }

                var renamed = ViewModel.AllProfiles.FirstOrDefault(p => p.SubscriptionGroup == group.Key && p.GroupTitleCustom);
                string customTitle = renamed != null ? renamed.GroupTitle : null;

                ViewModel.AllProfiles.RemoveAll(p => p.SubscriptionGroup == group.Key);
                foreach (var p in fetched)
                {
                    p.LastUpdated = DateTime.Now;
                    if (!string.IsNullOrEmpty(customTitle)) { p.GroupTitle = customTitle; p.GroupTitleCustom = true; }
                }
                ViewModel.AllProfiles.AddRange(fetched);

                ViewModel.SelectedProfile = null;
                ViewModel.UpdateGroupedUI();
                await ViewModel.SaveProfilesAsync();

                var issued = fetched[0];
                StatusText.Text = $"Проверяем {issued.Address}...";
                await PingService.PingAsync(issued);

                string ping = issued.CleanPingText ?? "";
                if (ping.StartsWith("Таймаут") || ping.StartsWith("Ошибка"))
                {
                    StatusText.Text = $"{chosen.Name}: сервер недоступен.";
                    await new ContentDialog
                    {
                        Title = "Сервер не отвечает",
                        Content = $"Страна переключена на {chosen.Name}, конфиг получен, но узел " +
                                  $"{issued.Address}:{issued.Port} не отвечает на подключение.",
                        PrimaryButtonText = "Понятно"
                    }.ShowAsync();
                }
                else
                {
                    StatusText.Text = $"Страна переключена: {chosen.Name} ({ping})";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Не удалось переключить страну.";
                await ShowAmneziaErrorAsync(ex);
            }
        }

        // ==================== ОТПРАВКА ЖУРНАЛОВ ====================

        private async void ShareLogBtn_Click(object sender, RoutedEventArgs e)
        {
            var files = await CollectLogFilesAsync();
            if (files.Count == 0)
            {
                ShareLogHint.Text = "Журнал пуст. Попробуйте подключиться к серверу и повторите отправку.";
                return;
            }

            _logFilesToShare = files;
            var names = new List<string>();
            foreach (var f in files) names.Add(f.Name);
            ShareLogHint.Text = "Отправляются файлы: " + string.Join(", ", names) + ".";

            var dtm = DataTransferManager.GetForCurrentView();
            dtm.DataRequested -= OnLogShareRequested;
            dtm.DataRequested += OnLogShareRequested;
            try
            {
                DataTransferManager.ShowShareUI();
            }
            catch (Exception ex)
            {
                ShareLogHint.Text = "Не удалось открыть окно отправки: " + ex.Message;
            }
        }

        private void OnLogShareRequested(DataTransferManager sender, DataRequestedEventArgs args)
        {
            var files = _logFilesToShare;
            if (files == null || files.Count == 0)
            {
                args.Request.FailWithDisplayText("Журнал пуст.");
                return;
            }
            var data = args.Request.Data;
            data.Properties.Title = "Журнал MetroBox";
            data.Properties.Description = AppLog.EnvironmentInfo();
            data.SetStorageItems(files);
        }

        private static async Task<List<StorageFile>> CollectLogFilesAsync()
        {
            var names = new[] { AppLog.LogFileName, "vpnlog.txt", "vpnlog.prev.txt", AmneziaApi.LogFileName };
            var folder = ApplicationData.Current.LocalFolder;
            var result = new List<StorageFile>();
            foreach (var name in names)
            {
                try
                {
                    var file = await folder.TryGetItemAsync(name) as StorageFile;
                    if (file == null) continue;
                    var props = await file.GetBasicPropertiesAsync();
                    if (props.Size > 0) result.Add(file);
                }
                catch { }
            }
            return result;
        }

        internal static bool IsRefreshableGroup(string group) => MainViewModel.IsRefreshableGroup(group);
        internal static bool IsAutoRefreshableGroup(string group) => MainViewModel.IsAutoRefreshableGroup(group);
    }
}
