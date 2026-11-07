using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Collections.Generic;
using Windows.UI.Xaml;

namespace VlessApp
{
    public class ProfileGroup : ObservableCollection<VlessProfile>
    {
        public string Key { get; set; }

        private bool _isExpanded = true;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsExpanded)));
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(ArrowIcon)));
                    ToggleItems();
                }
            }
        }

        public string ArrowIcon => IsExpanded ? "\uE70D" : "\uE76C";

        // \u0427\u0442\u043E \u043F\u043E\u043A\u0430\u0437\u044B\u0432\u0430\u0442\u044C \u0432 \u0448\u0430\u043F\u043A\u0435. \u041A\u043B\u044E\u0447\u043E\u043C \u0433\u0440\u0443\u043F\u043F\u044B \u0441\u043B\u0443\u0436\u0438\u0442 \u0441\u0441\u044B\u043B\u043A\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438, \u0438 \u0434\u043E
        // \u044D\u0442\u043E\u0433\u043E \u043E\u043D\u0430 \u043F\u043E\u043F\u0430\u0434\u0430\u043B\u0430 \u0432 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A \u043A\u0430\u043A \u0435\u0441\u0442\u044C \u2014 \u0443 \u0441\u0441\u044B\u043B\u043E\u043A Amnezia \u0432 \u043D\u0451\u043C
        // \u043E\u0441\u0442\u0430\u0432\u0430\u043B\u043E\u0441\u044C \u00ABvpn:/\u00BB, \u0443 \u043E\u0431\u044B\u0447\u043D\u044B\u0445 \u043F\u043E\u0434\u043F\u0438\u0441\u043E\u043A \u2014 \u0432\u0435\u0441\u044C URL.
        public string Title
        {
            get
            {
                if (_allItems.Count > 0 && !string.IsNullOrWhiteSpace(_allItems[0].GroupTitle))
                    return _allItems[0].GroupTitle;
                return FriendlyName(Key);
            }
        }

        public static string FriendlyName(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return "\u0411\u0435\u0437 \u0433\u0440\u0443\u043F\u043F\u044B";

            if (key.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase))
                return "\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 Amnezia";

            if (key.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string forUri = key.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase)
                        ? "https://" + key.Substring("ssconf://".Length)
                        : key;
                    string host = new Uri(forUri).Host;
                    if (!string.IsNullOrEmpty(host)) return host;
                }
                catch { }
            }
            return key;
        }

        public string LastUpdatedText
        {
            get
            {
                if (_allItems.Count == 0) return "Импортировано: не обновлялось";
                string when = _allItems[0].LastUpdated.ToString("dd.MM.yyyy HH:mm");
                if (MainPage.IsAutoRefreshableGroup(Key)) return when + " | Автообновление - 1 ч.";
                if (MainPage.IsRefreshableGroup(Key)) return when + " | Только вручную";
                return when;
            }
        }

        public bool IsAmnezia => !string.IsNullOrEmpty(Key) &&
                                Key.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase);

        public Visibility CountryPickerVisibility => IsAmnezia ? Visibility.Visible : Visibility.Collapsed;

        // Счётчик устройств и срок подписки — приходят от шлюза вместе с конфигом.
        public string AmneziaInfo => _allItems.Count > 0 ? _allItems[0].AmneziaInfo : "";

        public Visibility AmneziaInfoVisibility => !string.IsNullOrEmpty(AmneziaInfo)
            ? Visibility.Visible : Visibility.Collapsed;

        public string Description => _allItems.Count > 0 ? _allItems[0].Description : "";
        public string InfoUrl => _allItems.Count > 0 ? _allItems[0].InfoUrl : "";
        public string TelegramUrl => _allItems.Count > 0 ? _allItems[0].TelegramUrl : "";

        public Visibility InfoButtonsVisibility => (!string.IsNullOrEmpty(InfoUrl) || !string.IsNullOrEmpty(TelegramUrl))
            ? Visibility.Visible : Visibility.Collapsed;

        public Visibility DescriptionVisibility => !string.IsNullOrEmpty(Description)
            ? Visibility.Visible : Visibility.Collapsed;

        private List<VlessProfile> _allItems = new List<VlessProfile>();

        public void SetAllItems(IEnumerable<VlessProfile> items)
        {
            _allItems = items.ToList();
            ToggleItems();
        }

        private void ToggleItems()
        {
            this.Clear();
            if (IsExpanded)
            {
                foreach (var item in _allItems)
                {
                    this.Add(item);
                }
            }
        }
    }

}
