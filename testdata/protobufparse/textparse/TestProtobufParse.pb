help "go_build_info" "Build information about the main Go module."
type "go_build_info" gauge
series "go_build_infoÿchecksumÿÿpathÿgithub.com/prometheus/client_golangÿversionÿ(devel)" 3ff0000000000000 - "__name__"="go_build_info" "checksum"="" "path"="github.com/prometheus/client_golang" "version"="(devel)"
st 0
help "go_memstats_alloc_bytes_total" "Total number of bytes allocated, even if freed."
unit "go_memstats_alloc_bytes_total" "bytes"
type "go_memstats_alloc_bytes_total" counter
series "go_memstats_alloc_bytes_total" 4137993000000000 - "__name__"="go_memstats_alloc_bytes_total"
exemplar 4028000000000000 1625851151233 "dummyID"="42"
st 0
help "something_untyped" "Just to test the untyped type."
type "something_untyped" unknown
series "something_untyped" 4045000000000000 1234567 "__name__"="something_untyped"
st 0
help "test_histogram" "Test histogram with many buckets removed to keep it manageable in size."
type "test_histogram" histogram
histogram "test_histogram" 1234568 int schema=3 count=175 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=2 hint=0 pos_spans=[-161:1,8:3] pos=[1,2,-1,-1] neg_spans=[-162:1,23:4] neg=[1,3,-2,-1,1] custom=[] "__name__"="test_histogram"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59727"
st 0
help "test_gauge_histogram" "Like test_histogram but as gauge histogram."
type "test_gauge_histogram" gaugehistogram
histogram "test_gauge_histogram" 1234568 int schema=3 count=175 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=2 hint=3 pos_spans=[-161:1,8:3] pos=[1,2,-1,-1] neg_spans=[-162:1,23:4] neg=[1,3,-2,-1,1] custom=[] "__name__"="test_gauge_histogram"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59727"
st 0
help "test_float_histogram" "Test float histogram with many buckets removed to keep it manageable in size."
type "test_float_histogram" histogram
histogram "test_float_histogram" 1234568 float schema=3 count=4065e00000000000 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=4000000000000000 hint=0 pos_spans=[-161:1,8:3] pos=[3ff0000000000000,4000000000000000,bff0000000000000,bff0000000000000] neg_spans=[-162:1,23:4] neg=[3ff0000000000000,4008000000000000,c000000000000000,bff0000000000000,3ff0000000000000] custom=[] "__name__"="test_float_histogram"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59727"
st 0
help "test_gauge_float_histogram" "Like test_float_histogram but as gauge histogram."
type "test_gauge_float_histogram" gaugehistogram
histogram "test_gauge_float_histogram" 1234568 float schema=3 count=4065e00000000000 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=4000000000000000 hint=3 pos_spans=[-161:1,8:3] pos=[3ff0000000000000,4000000000000000,bff0000000000000,bff0000000000000] neg_spans=[-162:1,23:4] neg=[3ff0000000000000,4008000000000000,c000000000000000,bff0000000000000,3ff0000000000000] custom=[] "__name__"="test_gauge_float_histogram"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59727"
st 0
help "test_histogram2" "Similar histogram as before but now without sparse buckets."
type "test_histogram2" histogram
histogram "test_histogram2" - int schema=-53 count=175 sum=3f4b21c475e6362a zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:4] pos=[2,0,10,147] neg_spans=[] neg=[] custom=[bf3f75104d551d69,bf38e757928e0c9e,3ff0000000000000] "__name__"="test_histogram2"
exemplar bf38e757928e0c9e 1625851153146 "dummyID"="59727"
st 0
help "test_histogram3" "Similar histogram as before but now with integer buckets."
type "test_histogram3" histogram
histogram "test_histogram3" - int schema=-53 count=6 sum=4049000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:3] pos=[2,0,0] neg_spans=[] neg=[] custom=[c034000000000000,4034000000000000,403e000000000000] "__name__"="test_histogram3"
exemplar 402e000000000000 1625851153146 "dummyID"="59727"
st 0
help "test_histogram_family" "Test histogram metric family with two very simple histograms."
type "test_histogram_family" histogram
histogram "test_histogram_familyÿfooÿbar" - int schema=3 count=5 sum=4028333333333333 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[8:2] pos=[2,1] neg_spans=[] neg=[] custom=[] "__name__"="test_histogram_family" "foo"="bar"
st 0
histogram "test_histogram_familyÿfooÿbaz" - int schema=3 count=6 sum=402a333333333333 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[8:2] pos=[1,4] neg_spans=[] neg=[] custom=[] "__name__"="test_histogram_family" "foo"="baz"
st 0
help "test_float_histogram_with_zerothreshold_zero" "Test float histogram with a zero threshold of zero."
type "test_float_histogram_with_zerothreshold_zero" histogram
histogram "test_float_histogram_with_zerothreshold_zero" - float schema=3 count=4014000000000000 sum=4028333333333333 zero_threshold=0000000000000000 zero_count=0000000000000000 hint=0 pos_spans=[8:2] pos=[4000000000000000,4008000000000000] neg_spans=[] neg=[] custom=[] "__name__"="test_float_histogram_with_zerothreshold_zero"
st 0
help "rpc_durations_seconds" "RPC latency distributions."
type "rpc_durations_seconds" summary
series "rpc_durations_seconds_countÿserviceÿexponential" 4070600000000000 - "__name__"="rpc_durations_seconds_count" "service"="exponential"
st 0
series "rpc_durations_seconds_sumÿserviceÿexponential" 3f30beca61c1da9b - "__name__"="rpc_durations_seconds_sum" "service"="exponential"
st 0
series "rpc_durations_secondsÿquantileÿ0.5ÿserviceÿexponential" 3ea59e4fb26afc41 - "__name__"="rpc_durations_seconds" "quantile"="0.5" "service"="exponential"
st 0
series "rpc_durations_secondsÿquantileÿ0.9ÿserviceÿexponential" 3ec04dcb4485c347 - "__name__"="rpc_durations_seconds" "quantile"="0.9" "service"="exponential"
st 0
series "rpc_durations_secondsÿquantileÿ0.99ÿserviceÿexponential" 3ed0f99b1bacc7ee - "__name__"="rpc_durations_seconds" "quantile"="0.99" "service"="exponential"
st 0
help "without_quantiles" "A summary without quantiles."
type "without_quantiles" summary
series "without_quantiles_count" 4045000000000000 - "__name__"="without_quantiles_count"
st 0
series "without_quantiles_sum" 3ff3be76c8b43958 - "__name__"="without_quantiles_sum"
st 0
help "empty_histogram" "A histogram without observations and with a zero threshold of zero but with a no-op span to identify it as a native histogram."
type "empty_histogram" histogram
histogram "empty_histogram" - int schema=0 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="empty_histogram"
st 0
help "test_counter_with_createdtimestamp" "A counter with a created timestamp."
type "test_counter_with_createdtimestamp" counter
series "test_counter_with_createdtimestamp" 4045000000000000 - "__name__"="test_counter_with_createdtimestamp"
st 1625851153146
help "test_summary_with_createdtimestamp" "A summary with a created timestamp."
type "test_summary_with_createdtimestamp" summary
series "test_summary_with_createdtimestamp_count" 4045000000000000 - "__name__"="test_summary_with_createdtimestamp_count"
st 1625851153146
series "test_summary_with_createdtimestamp_sum" 3ff3be76c8b43958 - "__name__"="test_summary_with_createdtimestamp_sum"
st 1625851153146
help "test_histogram_with_createdtimestamp" "A histogram with a created timestamp."
type "test_histogram_with_createdtimestamp" histogram
histogram "test_histogram_with_createdtimestamp" - int schema=0 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="test_histogram_with_createdtimestamp"
st 1625851153146
help "test_gaugehistogram_with_createdtimestamp" "A gauge histogram with a created timestamp."
type "test_gaugehistogram_with_createdtimestamp" gaugehistogram
histogram "test_gaugehistogram_with_createdtimestamp" - int schema=0 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=3 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="test_gaugehistogram_with_createdtimestamp"
st 1625851153146
help "test_histogram_with_native_histogram_exemplars" "A histogram with native histogram exemplars."
type "test_histogram_with_native_histogram_exemplars" histogram
histogram "test_histogram_with_native_histogram_exemplars" 1234568 int schema=3 count=175 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=2 hint=0 pos_spans=[-161:1,8:3] pos=[1,2,-1,-1] neg_spans=[-162:1,23:4] neg=[1,3,-2,-1,1] custom=[] "__name__"="test_histogram_with_native_histogram_exemplars"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59780"
exemplar bf410a137f38c543 1625851160156 "dummyID"="59772"
st 0
help "test_histogram_with_native_histogram_exemplars2" "Another histogram with native histogram exemplars."
type "test_histogram_with_native_histogram_exemplars2" histogram
histogram "test_histogram_with_native_histogram_exemplars2" 1234568 int schema=3 count=175 sum=3f4b22279eab7b5d zero_threshold=37f0000000000000 zero_count=2 hint=0 pos_spans=[-161:1,8:3] pos=[1,2,-1,-1] neg_spans=[-162:1,23:4] neg=[1,3,-2,-1,1] custom=[] "__name__"="test_histogram_with_native_histogram_exemplars2"
exemplar bf398f1d3ed527e5 1625851155146 "dummyID"="59780"
st 0
