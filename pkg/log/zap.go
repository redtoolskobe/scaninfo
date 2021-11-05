package log

import (
	"os"
	"time"

	"github.com/redtoolskobe/scaninfo/pkg/common"

	"github.com/redtoolskobe/scaninfo/global"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Log() *zap.Logger {
	config := zapcore.EncoderConfig{
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(t.Format("2006-01-02 15:04:05"))
		}}
	//cfg := zap.NewProductionConfig()
	file, _ := os.Create(common.Rstfile + ".txt")
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config),
		zapcore.AddSync(file),
		zapcore.InfoLevel,
	)
	return zap.New(core)
}

func InitLog() {
	global.Log = Log()
}
