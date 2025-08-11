#鲁棒性测试（翻转/平移）
import os
import cv2
import numpy as np
import matplotlib.pyplot as plt

IMG_PATH   = 'data/lenna.jpg'
WM_PATH    = 'data/logo.png'
OUT_DIR    = 'results'
os.makedirs(OUT_DIR, exist_ok=True)

def dct2(block):
    return cv2.dct(np.float32(block))

def idct2(block):
    return cv2.idct(np.float32(block))

def psnr(img1, img2):
    mse = np.mean((img1 - img2) ** 2)
    if mse == 0:
        return float('inf')
    return 20 * np.log10(255 / np.sqrt(mse))

def ncc(w1, w2):
    w1 = w1.flatten()
    w2 = w2.flatten()
    return np.corrcoef(w1, w2)[0, 1]

#水印嵌入
def embed_watermark(host_img: np.ndarray, wm: np.ndarray, alpha=20):
    H, W = host_img.shape[:2]
    h, w = wm.shape
    assert (H >= h*8) and (W >= w*8), "载体尺寸不足"

    host = host_img.copy()
    ycrcb = cv2.cvtColor(host, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)
    y = y.astype(np.float32)

    wm_bits = wm.astype(np.int8) * 2 - 1  # 1 / -1
    for i in range(h):
        for j in range(w):
            x0, y0 = i*8, j*8
            blk = y[x0:x0+8, y0:y0+8]
            d = dct2(blk)
            d[2, 1] += alpha * wm_bits[i, j]
            y[x0:x0+8, y0:y0+8] = idct2(d)

    out = cv2.merge([np.clip(y, 0, 255).astype(np.uint8), cr, cb])
    return cv2.cvtColor(out, cv2.COLOR_YCrCb2BGR)

#提取水印
def extract_watermark(attacked: np.ndarray, wm_shape):
    h, w = wm_shape
    ycrcb = cv2.cvtColor(attacked, cv2.COLOR_BGR2YCrCb)
    y = cv2.split(ycrcb)[0].astype(np.float32)

    wm_bits = np.zeros((h, w), dtype=np.int8)
    for i in range(h):
        for j in range(w):
            blk = y[i*8:i*8+8, j*8:j*8+8]
            wm_bits[i, j] = 1 if dct2(blk)[2, 1] > 0 else 0
    return wm_bits

def flip(img, code):
    return cv2.flip(img, code)

def translate(img, dx, dy):
    M = np.float32([[1, 0, dx], [0, 1, dy]])
    return cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))

def main():
    host = cv2.imread(IMG_PATH)
    wm   = cv2.imread(WM_PATH, 0)
    _, wm_bin = cv2.threshold(wm, 127, 1, cv2.THRESH_BINARY)

    #嵌入
    watermarked = embed_watermark(host, wm_bin, alpha=20)
    cv2.imwrite(f'{OUT_DIR}/watermarked.png', watermarked)
    print('PSNR(host, watermarked) = %.2f dB' % psnr(host, watermarked))

    #提取
    wm_ext = extract_watermark(watermarked, wm_bin.shape)
    print('NCC(no attack) = %.3f' % ncc(wm_bin, wm_ext))

    #攻击与鲁棒性测试
    attacks = {
        'flip_h'   : lambda x: flip(x, 0),
        'flip_v'   : lambda x: flip(x, 1),
        'flip_b'   : lambda x: flip(x, -1),
        'shift_x20': lambda x: translate(x, 20, 0),
        'shift_y20': lambda x: translate(x, 0, 20),
        'shift_xy' : lambda x: translate(x, 15, 15)
    }

    ncc_scores = []
    for name, atk in attacks.items():
        attacked = atk(watermarked)
        wm_rec   = extract_watermark(attacked, wm_bin.shape)
        ncc_val  = ncc(wm_bin, wm_rec)
        ncc_scores.append(ncc_val)
        cv2.imwrite(f'{OUT_DIR}/{name}.png', attacked)
        cv2.imwrite(f'{OUT_DIR}/{name}_extract.png', (wm_rec*255).astype(np.uint8))
        print(f'{name:10s}  NCC = {ncc_val:.3f}')

    #画图
    plt.figure(figsize=(8, 5))
    bars = plt.bar(attacks.keys(), ncc_scores, color='skyblue')
    for bar, v in zip(bars, ncc_scores):
        plt.text(bar.get_x()+bar.get_width()/2, v+0.01, f'{v:.2f}', ha='center')
    plt.ylim(0, 1.1)
    plt.ylabel('NCC')
    plt.title('Robustness Test (Flip & Translation)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{OUT_DIR}/robustness_bar.png')
    plt.show()

if __name__ == '__main__':
    main()