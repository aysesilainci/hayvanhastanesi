from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'Bsnrinci-789'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://@localhost/hastane?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Mail Ayarları
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Gmail için
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Gönderici e-posta
app.config['MAIL_PASSWORD'] = 'your_email_password'  # E-posta şifresi
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app)

# Token Oluşturucu
s = URLSafeTimedSerializer(app.secret_key)

# Models
class User(db.Model):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    telefon = db.Column(db.String(20))
    adres = db.Column(db.String(255))
    kayit_tarihi = db.Column(db.DateTime, default=db.func.now())
    role = db.Column(db.String(20), default='user')  # Kullanıcının rolü (varsayılan: 'user')

class Hayvan(db.Model):
    __tablename__ = 'Hayvanlar'
    hayvan_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id', ondelete='CASCADE'), nullable=False)
    turu = db.Column(db.String(50), nullable=False)
    cinsi = db.Column(db.String(50))
    ad = db.Column(db.String(100), nullable=False)  # Hayvan adı, boş geçilemez
    resim = db.Column(db.String(255), nullable=True)
    yas = db.Column(db.Integer)
    tibbi_gecmis = db.Column(db.Text)
    user = db.relationship('User', backref='hayvanlar', lazy=True)

class Veteriner(db.Model):
    __tablename__ = 'Veterinerler'
    veteriner_id = db.Column(db.Integer, primary_key=True)
    ad_soyad = db.Column(db.String(100), nullable=False)
    telefon = db.Column(db.String(20))
    email = db.Column(db.String(100), nullable=False, unique=True)
    image = db.Column(db.String(100), nullable=True)  # Opsiyonel resim yolu
    password = db.Column(db.String(255), nullable=False)  # Şifre alanı

class Randevu(db.Model):
    __tablename__ = 'Randevular'
    randevu_id = db.Column(db.Integer, primary_key=True)
    hayvan_id = db.Column(db.Integer, db.ForeignKey('Hayvanlar.hayvan_id', ondelete='CASCADE'), nullable=False)
    veteriner_id = db.Column(db.Integer, db.ForeignKey('Veterinerler.veteriner_id', ondelete='CASCADE'), nullable=False)
    tarih_saat = db.Column(db.DateTime, nullable=False)
    durum = db.Column(db.String(50), default='Bekliyor')
    notlar = db.Column(db.Text)
    hayvan = db.relationship('Hayvan', backref='randevular', lazy=True)
    veteriner = db.relationship('Veteriner', backref='randevular', lazy=True)

class Hizmet(db.Model):
    __tablename__ = 'Hizmetler'
    hizmet_id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(100), nullable=False)
    ucret = db.Column(db.Float, nullable=False)
    aciklama = db.Column(db.Text)

class RandevuHizmet(db.Model):
    __tablename__ = 'Randevu_Hizmetler'
    randevu_hizmet_id = db.Column(db.Integer, primary_key=True)
    randevu_id = db.Column(db.Integer, db.ForeignKey('Randevular.randevu_id', ondelete='CASCADE'), nullable=False)
    hizmet_id = db.Column(db.Integer, db.ForeignKey('Hizmetler.hizmet_id'), nullable=False)
    miktar = db.Column(db.Integer, nullable=False)
    toplam_tutar = db.Column(db.Float, nullable=False)

class Bildirim(db.Model):
    __tablename__ = 'Bildirimler'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id', ondelete='CASCADE'), nullable=True)
    veteriner_id = db.Column(db.Integer, db.ForeignKey('Veterinerler.veteriner_id', ondelete='CASCADE'), nullable=True)
    mesaj = db.Column(db.String(255), nullable=False)
    tarih = db.Column(db.DateTime, default=db.func.now())
    okundu = db.Column(db.Boolean, default=False)

class Not(db.Model):
    __tablename__ = 'Notlar'
    id = db.Column(db.Integer, primary_key=True)
    veteriner_id = db.Column(db.Integer, db.ForeignKey('Veterinerler.veteriner_id', ondelete='CASCADE'), nullable=False)
    baslik = db.Column(db.String(255), nullable=False)
    icerik = db.Column(db.Text, nullable=True)
    tarih = db.Column(db.DateTime, default=db.func.now())
    veteriner = db.relationship('Veteriner', backref='notlar', lazy=True)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role')  # Kullanıcı mı veteriner mi admin mi?

        # Kullanıcı giriş kontrolü
        if role == 'user':
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.user_id
                session['role'] = 'user'
                flash('Kullanıcı olarak giriş yaptınız.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
                return redirect(url_for('login'))

        # Veteriner giriş kontrolü
        elif role == 'veteriner':
            veteriner = Veteriner.query.filter_by(ad_soyad=username).first()
            if veteriner and veteriner.password and check_password_hash(veteriner.password, password):
                session['veteriner_id'] = veteriner.veteriner_id
                session['role'] = 'veteriner'
                flash('Veteriner olarak giriş yaptınız.', 'success')
                return redirect(url_for('veteriner_anasayfa'))  # Veteriner özel sayfasına yönlendirme
            else:
                flash('Geçersiz veteriner adı veya şifre.', 'danger')
                return redirect(url_for('login'))

        # Admin giriş kontrolü
        elif role == 'admin':
            admin_user = User.query.filter_by(username=username, role='admin').first()
            if admin_user and check_password_hash(admin_user.password_hash, password):
                session['user_id'] = admin_user.user_id
                session['role'] = 'admin'
                flash('Admin olarak giriş yaptınız.', 'success')
                return redirect(url_for('admin_dashboard'))  # Admin özel sayfasına yönlendirme
            else:
                flash('Geçersiz admin adı veya şifre.', 'danger')
                return redirect(url_for('login'))

        # Rol seçilmemişse uyarı ver
        else:
            flash('Lütfen bir rol seçin.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        users = User.query.all()  # Kullanıcılar
        veterinerler = Veteriner.query.all()  # Veterinerler
        return render_template('admin_dashboard.html', users=users, veterinerler=veterinerler)
    flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
    return redirect(url_for('login'))

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu işlemi yapma yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Kullanıcı başarıyla silindi.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu işlemi yapma yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash('Kullanıcı bilgileri başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_edit_user.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        telefon = request.form['telefon']
        adres = request.form['adres']

        # Şifre uzunluğu kontrolü
        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalıdır.', 'danger')
            return redirect(url_for('register'))

        # Şifre hashleme
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Kullanıcı adı kontrolü
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
            return redirect(url_for('register'))

        # E-posta kontrolü
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Bu e-posta adresi zaten kayıtlı.', 'danger')
            return redirect(url_for('register'))

        # Yeni kullanıcı oluşturma
        new_user = User(
            username=username,
            password_hash=hashed_password,
            email=email,
            telefon=telefon,
            adres=adres,
            role='user'  # Sabit olarak 'user' atanır
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/')
def index():
    veterinerler = Veteriner.query.all()
    user = None
    veteriner = None

    if 'user_id' in session and session['role'] == 'user':
        user = User.query.get(session['user_id'])
    elif 'veteriner_id' in session and session['role'] == 'veteriner':
        veteriner = Veteriner.query.get(session['veteriner_id'])

    return render_template('index.html', user=user, veteriner=veteriner, veterinerler=veterinerler)


@app.route('/veteriner_kayit', methods=['GET', 'POST'])
def veteriner_kayit():
    if request.method == 'POST':
        ad_soyad = request.form['ad_soyad']
        telefon = request.form['telefon']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Şifreler eşleşiyor mu?
        if password != confirm_password:
            flash('Şifreler eşleşmiyor. Lütfen tekrar deneyin.', 'danger')
            return redirect(url_for('veteriner_kayit'))

        # Veteriner bilgilerini doğrula
        veteriner = Veteriner.query.filter_by(ad_soyad=ad_soyad, telefon=telefon).first()
        if not veteriner:
            flash('Veteriner bilgileri bulunamadı. Lütfen doğru bilgileri girin.', 'danger')
            return redirect(url_for('veteriner_kayit'))

        # Şifre zaten var mı?
        if veteriner.password:
            flash('Bu veteriner zaten şifre oluşturmuş.', 'danger')
            return redirect(url_for('login'))

        # Şifreyi hashle ve kaydet
        veteriner.password = generate_password_hash(password)
        db.session.commit()
        flash('Şifre başarıyla oluşturuldu! Artık giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    return render_template('veteriner_kayit.html')



@app.route('/hayvanlarim', methods=['GET', 'POST'])
def hayvanlarim():
    if 'user_id' not in session:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('index'))

    user_id = session['user_id']

    if request.method == 'POST':
        try:
            ad = request.form['ad']  # Hayvan adı
            turu = request.form['turu']
            cinsi = request.form.get('cinsi')
            yas = request.form.get('yas', type=int)
            tibbi_gecmis = request.form.get('tibbi_gecmis')

            # Eksik bilgi kontrolü
            if not ad or not turu or not cinsi or yas is None:
                flash('Tüm alanları doldurmanız gerekiyor.', 'danger')
                return redirect(url_for('hayvanlarim'))

            # Resim dosyasını işleme
            resim = request.files['resim']
            if resim:
                # Benzersiz bir dosya adı oluştur ve resmi kaydet
                resim_dosya_adi = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{resim.filename}"
                resim.save(f"static/images/{resim_dosya_adi}")
                resim_yolu = f"images/{resim_dosya_adi}"
            else:
                resim_yolu = None  # Eğer resim yüklenmezse boş bırak

            # Yeni hayvan ekleme
            yeni_hayvan = Hayvan(
                user_id=user_id,
                ad=ad,
                turu=turu,
                cinsi=cinsi,
                yas=yas,
                tibbi_gecmis=tibbi_gecmis,
                resim=resim_yolu
            )
            db.session.add(yeni_hayvan)
            db.session.commit()
            flash('Hayvan başarıyla eklendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Bir hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('hayvanlarim'))

    # Kullanıcının tüm hayvanlarını sorgula
    hayvanlar = Hayvan.query.filter_by(user_id=user_id).all()
    return render_template('hayvanlarim.html', hayvanlar=hayvanlar)

@app.route('/hayvan_sil/<int:hayvan_id>', methods=['POST'])
def hayvan_sil(hayvan_id):
    if 'user_id' not in session:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('index'))

    # Hayvanı veritabanından al
    hayvan = Hayvan.query.get_or_404(hayvan_id)

    # Kullanıcının yetkisi kontrol ediliyor
    if hayvan.user_id != session['user_id']:
        flash('Bu hayvanı silme yetkiniz yok.', 'danger')
        return redirect(url_for('hayvanlarim'))

    # Hayvana bağlı tüm randevuları sil
    randevular = Randevu.query.filter_by(hayvan_id=hayvan_id).all()
    for randevu in randevular:
        db.session.delete(randevu)

    # Resim dosyasını sil
    if hayvan.resim:
        resim_dosya_yolu = os.path.join('static', hayvan.resim)
        if os.path.exists(resim_dosya_yolu):
            os.remove(resim_dosya_yolu)

    # Hayvanı veritabanından sil
    db.session.delete(hayvan)
    try:
        db.session.commit()
        flash('Hayvan ve ilgili randevular başarıyla silindi.', 'success')
    except Exception:
        db.session.rollback()
        flash('Bir hata oluştu. Hayvan silinemedi.', 'danger')

    return redirect(url_for('hayvanlarim'))

@app.route('/profil')
def profil():
    if 'role' in session:
        if session['role'] == 'user':
            user = User.query.get(session['user_id'])
            return render_template('profil.html', user=user)
        elif session['role'] == 'veteriner':
            veteriner = Veteriner.query.get(session['veteriner_id'])
            return render_template('profil.html', veteriner=veteriner)
    flash('Lütfen giriş yapın.', 'warning')
    return redirect(url_for('login'))

@app.route('/duzenle_profil/<field>', methods=['GET', 'POST'])
def duzenle_profil(field):
    if 'user_id' not in session:
        flash('Lütfen giriş yapın.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_value = request.form['new_value']
        if session['role'] == 'user':
            user = User.query.get(session['user_id'])
            setattr(user, field, new_value)
        elif session['role'] == 'veteriner':
            veteriner = Veteriner.query.get(session['veteriner_id'])
            setattr(veteriner, field, new_value)
        db.session.commit()
        flash('Bilgiler başarıyla güncellendi!', 'success')
        return redirect(url_for('profil'))

    return render_template('duzenle_profil.html', field=field)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('veteriner_id', None)
    session.pop('role', None)
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']
    print(f"Ad: {name}, E-posta: {email}, Mesaj: {message}")
    flash("Mesajınız alındı! En kısa sürede size geri döneceğiz.", "success")
    return redirect(url_for('index'))

def bildirim_ekle_kullanici(user_id, mesaj):
    yeni_bildirim = Bildirim(user_id=user_id, mesaj=mesaj)
    db.session.add(yeni_bildirim)
    db.session.commit()

def bildirim_ekle_veteriner(veteriner_id, mesaj):
    yeni_bildirim = Bildirim(veteriner_id=veteriner_id, mesaj=mesaj)
    db.session.add(yeni_bildirim)
    db.session.commit()

def bildirimleri_getir_kullanici(user_id):
    return Bildirim.query.filter_by(user_id=user_id, okundu=False).order_by(Bildirim.tarih.desc()).all()

def bildirimleri_getir_veteriner(veteriner_id):
    return Bildirim.query.filter_by(veteriner_id=veteriner_id, okundu=False).order_by(Bildirim.tarih.desc()).all()

def bildirim_okundu(bildirim_id):
    bildirim = Bildirim.query.get(bildirim_id)
    if bildirim:
        bildirim.okundu = True
        db.session.commit()

@app.route('/bildirimler')
def bildirimler():
    if 'user_id' in session and session['role'] == 'user':
        bildirimler = bildirimleri_getir_kullanici(session['user_id'])
        return render_template('bildirimler.html', bildirimler=bildirimler)
    elif 'veteriner_id' in session and session['role'] == 'veteriner':
        bildirimler = bildirimleri_getir_veteriner(session['veteriner_id'])
        return render_template('bildirimler.html', bildirimler=bildirimler)
    else:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('login'))

@app.route('/bildirim_okundu/<int:bildirim_id>', methods=['POST'])
def bildirim_okundu_istek(bildirim_id):
    bildirim_okundu(bildirim_id)
    flash('Bildirim okundu olarak işaretlendi.', 'success')
    return redirect(url_for('bildirimler'))

from datetime import datetime, time
from flask import render_template, request, redirect, url_for, flash, session
from sqlalchemy.orm import joinedload

# Veteriner Anasayfa
@app.route('/veteriner_anasayfa', methods=['GET', 'POST'])
def veteriner_anasayfa():
    # Kullanıcı oturumu ve rol kontrolü
    if 'veteriner_id' not in session or session.get('role') != 'veteriner':
        flash('Lütfen giriş yapın.', 'danger')
        return redirect(url_for('login'))

    # Oturumdan veteriner ID'sini al
    veteriner_id = session['veteriner_id']
    veteriner = Veteriner.query.get(veteriner_id)

    # Sadece gelecek tarihlerdeki en yakın randevuları getir
    en_yakin_randevular = (
        Randevu.query.filter(
            Randevu.veteriner_id == veteriner_id,
            Randevu.tarih_saat >= datetime.now(),  # Şimdiki zamandan sonraki randevular
            Randevu.durum.in_(["Bekliyor", "Onaylandı"])  # "İptal Edildi" hariç
        )
        .order_by(Randevu.tarih_saat)  # Tarihe göre sıralama
        .limit(5)
        .all()
    )

    # Veterinere ait tüm notları getir
    notlar = (
        Not.query.filter_by(veteriner_id=veteriner_id)
        .order_by(Not.tarih.desc())  # En yeni notlar önce
        .all()
    )

    # Yeni not ekleme işlemi
    if request.method == 'POST':
        yeni_not_icerik = request.form.get('icerik')
        if yeni_not_icerik and yeni_not_icerik.strip():  # İçeriğin boş olup olmadığını kontrol et
            yeni_not = Not(
                veteriner_id=veteriner_id,
                baslik='Yeni Not',
                icerik=yeni_not_icerik.strip()
            )
            db.session.add(yeni_not)
            db.session.commit()
            flash('Not başarıyla kaydedildi!', 'success')
        else:
            flash('Not eklemek için içerik boş bırakılamaz.', 'danger')

    # Sayfayı render et
    return render_template(
        'veteriner_anasayfa.html',
        veteriner=veteriner,
        randevular=en_yakin_randevular,
        notlar=notlar
    )


# Veteriner Randevuları
@app.route('/veteriner_randevulari', methods=['GET'])
def veteriner_randevulari():
    # Veteriner kontrolü
    if 'veteriner_id' not in session or session.get('role') != 'veteriner':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    veteriner_id = session['veteriner_id']

    # Randevuları filtrele: Sadece "Bekliyor" ve "Onaylandı" durumundakiler
    randevular = Randevu.query.options(
        joinedload(Randevu.hayvan)
    ).filter(
        Randevu.veteriner_id == veteriner_id,
        Randevu.durum.in_(["Bekliyor", "Onaylandı"])
    ).order_by(Randevu.tarih_saat).all()

    # Takvim için randevuları formatla
    takvim_randevular = [
        {
            "title": f"{randevu.hayvan.ad} ({randevu.durum})",
            "start": randevu.tarih_saat.strftime('%Y-%m-%dT%H:%M:%S'),
            "backgroundColor": "#4caf50" if randevu.durum == "Onaylandı" else "#ffc107",  # Duruma göre renk
        }
        for randevu in randevular
    ]

    # Şablona gönder: randevular ve takvim verisi
    return render_template(
        'veteriner_randevulari.html',
        randevular=randevular,
        takvim_randevular=takvim_randevular
    )

# Kullanıcı Randevuları
@app.route('/randevularim', methods=['GET', 'POST'])
def randevularim():
    if 'veteriner_id' in session and session.get('role') == 'veteriner':
        return redirect(url_for('veteriner_randevulari'))

    if 'user_id' in session and session.get('role') == 'user':
        user_id = session['user_id']
        hayvanlar = Hayvan.query.filter_by(user_id=user_id).all()
        veterinerler = Veteriner.query.all()
        hizmetler = Hizmet.query.all()

        if request.method == 'POST':
            try:
                hayvan_id = request.form.get('hayvan_id')
                veteriner_id = request.form.get('veteriner_id')
                tarih_saat = request.form.get('tarih_saat')
                notlar = request.form.get('notlar')
                secilen_hizmetler = request.form.getlist('hizmetler')

                if not hayvan_id or not veteriner_id or not tarih_saat:
                    flash('Tüm alanları doldurduğunuzdan emin olun.', 'danger')
                    return redirect(url_for('randevularim'))

                randevu_tarih_saat = datetime.strptime(tarih_saat, '%Y-%m-%dT%H:%M')
                if not (time(8, 0) <= randevu_tarih_saat.time() <= time(17, 0)):
                    flash('Randevu saati, çalışma saatleri (08:00 - 17:00) arasında olmalıdır.', 'danger')
                    return redirect(url_for('randevularim'))

                yeni_randevu = Randevu(
                    hayvan_id=hayvan_id,
                    veteriner_id=veteriner_id,
                    tarih_saat=randevu_tarih_saat,
                    notlar=notlar
                )
                db.session.add(yeni_randevu)
                db.session.commit()

                for hizmet_id in secilen_hizmetler:
                    hizmet = Hizmet.query.get(hizmet_id)
                    if hizmet:
                        randevu_hizmet = RandevuHizmet(
                            randevu_id=yeni_randevu.randevu_id,
                            hizmet_id=hizmet.hizmet_id,
                            miktar=1,
                            toplam_tutar=hizmet.ucret
                        )
                        db.session.add(randevu_hizmet)
                db.session.commit()

                # Hayvan adını al
                hayvan = Hayvan.query.get(hayvan_id)

                # Bildirim ekleme işlemi (Kullanıcı ve Veteriner için)
                kullanici_mesaj = f"Yeni bir randevu oluşturuldu: {randevu_tarih_saat.strftime('%d/%m/%Y %H:%M')}"
                veteriner_mesaj = f"Yeni bir randevu talebi alındı: {randevu_tarih_saat.strftime('%d/%m/%Y %H:%M')}, Hayvan: {hayvan.ad}"

                # Kullanıcıya bildirim
                bildirim_ekle_kullanici(user_id, kullanici_mesaj)

                # Veterinere bildirim
                bildirim_ekle_veteriner(veteriner_id, veteriner_mesaj)

                flash('Randevunuz başarıyla oluşturuldu.', 'success')

            except Exception as e:
                db.session.rollback()
                flash(f'Bir hata oluştu: {str(e)}', 'danger')

        # Randevuları filtrele ve sadece "Bekliyor" ve "Onaylandı" durumundakileri listele
        randevular = Randevu.query.options(
            joinedload(Randevu.hayvan),
            joinedload(Randevu.veteriner)
        ).filter(
            Randevu.hayvan_id.in_([hayvan.hayvan_id for hayvan in hayvanlar]),
            Randevu.durum.in_(["Bekliyor", "Onaylandı"])
        ).all()

        return render_template(
            'randevularim.html',
            randevular=randevular,
            hayvanlar=hayvanlar,
            veterinerler=veterinerler,
            hizmetler=hizmetler
        )

    flash('Lütfen giriş yapın.', 'warning')
    return redirect(url_for('login'))


# Randevu İptal
@app.route('/randevu_iptal/<int:randevu_id>', methods=['POST'])
def randevu_iptal(randevu_id):
    # Kullanıcı veya veteriner giriş kontrolü
    if 'user_id' not in session and 'veteriner_id' not in session:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('login'))

    # Randevuyu veritabanından al
    randevu = Randevu.query.get_or_404(randevu_id)

    # Eğer kullanıcı giriş yapmışsa
    if 'user_id' in session and session.get('role') == 'user':
        hayvan = Hayvan.query.get(randevu.hayvan_id)
        if hayvan.user_id != session['user_id']:
            flash('Bu randevuyu iptal etme yetkiniz yok.', 'danger')
            return redirect(url_for('randevularim'))

    # Eğer veteriner giriş yapmışsa
    elif 'veteriner_id' in session and session.get('role') == 'veteriner':
        if randevu.veteriner_id != session['veteriner_id']:
            flash('Sadece kendi randevularınızı iptal edebilirsiniz.', 'danger')
            return redirect(url_for('veteriner_randevulari'))

    # Randevunun durumunu "İptal Edildi" olarak işaretle
    try:
        randevu.durum = "İptal Edildi"
        db.session.commit()
        flash('Randevu başarıyla iptal edildi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Randevu iptal edilirken bir hata oluştu: {str(e)}', 'danger')

    # Doğru sayfaya yönlendir
    if 'user_id' in session:
        return redirect(url_for('randevularim'))
    elif 'veteriner_id' in session:
        return redirect(url_for('veteriner_randevulari'))

@app.route('/not_ekle', methods=['POST'])
def not_ekle():
    veteriner_id = session.get('veteriner_id')
    if not veteriner_id:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('login'))

    icerik = request.form.get('icerik')
    if icerik:
        yeni_not = Not(veteriner_id=veteriner_id, baslik='Yeni Not', icerik=icerik)
        db.session.add(yeni_not)
        db.session.commit()
        flash('Not başarıyla eklendi.', 'success')
    else:
        flash('Not eklemek için içerik boş olamaz.', 'danger')

    return redirect(url_for('veteriner_anasayfa'))

@app.route('/not_sil/<int:not_id>', methods=['POST'])
def not_sil(not_id):
    veteriner_id = session.get('veteriner_id')
    if not veteriner_id:
        flash('Lütfen giriş yapın.', 'warning')
        return redirect(url_for('login'))

    silinecek_not = Not.query.get_or_404(not_id)

    # Notun sahibi kontrolü
    if silinecek_not.veteriner_id != veteriner_id:
        flash('Bu notu silme yetkiniz yok.', 'danger')
        return redirect(url_for('veteriner_anasayfa'))

    db.session.delete(silinecek_not)
    db.session.commit()
    flash('Not başarıyla silindi.', 'success')
    return redirect(url_for('veteriner_anasayfa'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Token oluştur
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # E-posta gönder
            msg = Message('Şifre Sıfırlama Talimatları', recipients=[email])
            msg.body = f'Şifrenizi sıfırlamak için şu bağlantıya tıklayın: {reset_url}'
            mail.send(msg)

            flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.', 'info')
        else:
            flash('Bu e-posta adresiyle eşleşen bir kullanıcı bulunamadı.', 'danger')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 saatlik süre
    except Exception:
        flash('Geçersiz veya süresi dolmuş bağlantı.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Şifreler eşleşmiyor.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash('Şifreniz başarıyla sıfırlandı.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/create_admin', methods=['GET'])
def create_admin():
    from werkzeug.security import generate_password_hash

    # Yeni admin kullanıcısını ekleyin
    existing_admin = User.query.filter_by(username='admin').first()
    if existing_admin:
        return "Admin zaten mevcut."

    new_admin = User(
        username='admin',
        password_hash=generate_password_hash('admin123'),  # Şifre: admin123
        email='admin@example.com',
        role='admin'  # Admin rolü
    )
    db.session.add(new_admin)
    db.session.commit()
    return "Admin başarıyla oluşturuldu!"

@app.route('/admin/veterinerler', methods=['GET'])
def admin_veterinerler():
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    veterinerler = Veteriner.query.all()
    return render_template('admin_veterinerler.html', veterinerler=veterinerler)

@app.route('/admin/veteriner_duzenle/<int:veteriner_id>', methods=['GET', 'POST'])
def admin_veteriner_duzenle(veteriner_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    veteriner = Veteriner.query.get_or_404(veteriner_id)

    if request.method == 'POST':
        veteriner.ad_soyad = request.form['ad_soyad']
        veteriner.email = request.form['email']
        veteriner.telefon = request.form['telefon']
        db.session.commit()
        flash('Veteriner bilgileri başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_veterinerler'))

    return render_template('admin_veteriner_duzenle.html', veteriner=veteriner)

@app.route('/admin/veteriner_sil/<int:veteriner_id>', methods=['POST'])
def admin_veteriner_sil(veteriner_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    veteriner = Veteriner.query.get_or_404(veteriner_id)
    db.session.delete(veteriner)
    db.session.commit()
    flash('Veteriner başarıyla silindi.', 'success')
    return redirect(url_for('admin_veterinerler'))

@app.route('/admin_add_veteriner', methods=['GET', 'POST'])
def admin_add_veteriner():
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu işlemi gerçekleştirme yetkiniz yok.', 'danger')
        return redirect(url_for('login'))  # Admin girişi yapmamışsa yönlendirme

    if request.method == 'POST':
        ad_soyad = request.form['ad_soyad']
        telefon = request.form['telefon']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Şifre doğrulama
        if password != confirm_password:
            flash('Şifreler eşleşmiyor. Lütfen tekrar deneyin.', 'danger')
            return redirect(url_for('admin_add_veteriner'))

        # Email kontrolü
        if Veteriner.query.filter_by(email=email).first():
            flash('Bu e-posta adresi zaten kayıtlı.', 'danger')
            return redirect(url_for('admin_add_veteriner'))

        # Yeni veteriner oluşturma
        yeni_veteriner = Veteriner(
            ad_soyad=ad_soyad,
            telefon=telefon,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(yeni_veteriner)
        db.session.commit()
        flash('Veteriner başarıyla eklendi.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_add_veteriner.html')

@app.route('/admin_reset_password/<int:user_id>', methods=['POST'])
def admin_reset_password(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Bu işlemi gerçekleştirme yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    # Kullanıcıyı al
    user = User.query.get(user_id)
    if not user:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Form verilerini al
    new_password = request.form.get('new_password')
    if not new_password:
        flash('Şifre alanı boş olamaz.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Şifreyi güncelle
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash(f'{user.username} kullanıcısının şifresi başarıyla sıfırlandı.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(debug=True)
