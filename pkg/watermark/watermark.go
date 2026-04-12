package watermark

import (
	"bytes"
	"image"
	"image/jpeg"
	"image/png"
	"io"

	"github.com/fogleman/gg"
)

// AddTextWatermark 为图片添加文本水印，返回新的图片字节流
// 支持格式：PNG, JPEG
func AddTextWatermark(reader io.Reader, text string, outputFormat string) ([]byte, error) {
	// 解码图片
	img, _, err := image.Decode(reader)
	if err != nil {
		return nil, err
	}

	// 创建绘图上下文
	dc := gg.NewContextForImage(img)
	// 设置水印样式
	fontSize := float64(img.Bounds().Dy()) / 20
	if fontSize < 12 {
		fontSize = 12
	}
	dc.SetRGBA(0.5, 0.5, 0.5, 0.5) // 灰色

	if err := dc.LoadFontFace("./fonts/1_Minecraft-Regular.otf", fontSize); err != nil {
		// 使用默认字体
		dc.SetRGBA(0, 0, 0, 0.5)
	}
	// 计算水印位置（右下角）
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	dc.DrawStringAnchored(text, float64(w)-10, float64(h)-16, 1, 1)

	// 编码输出
	buf := new(bytes.Buffer)
	switch outputFormat {
	case "png":
		err = png.Encode(buf, dc.Image())
	default:
		err = jpeg.Encode(buf, dc.Image(), &jpeg.Options{Quality: 90})
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AddTextWatermarkSimple 通用文本水印（返回带水印的文本，用于非图片文件，可选）
// 这里只做简单封装，实际可根据需要扩展
func AddTextWatermarkSimple(content []byte, watermark string) []byte {
	// 简单示例：在文件开头插入水印注释（仅适用于文本文件）
	prefix := []byte("# Watermark: " + watermark + "\n")
	return append(prefix, content...)
}
