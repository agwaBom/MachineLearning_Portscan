#기존 데이터 삭제 R
cat("\014")
rm(list=ls(all=TRUE))

library(MASS)
library(caret)
#library(ggplot2)

ds_PortScan <- read.csv2("/Users/hyunjinkim/dev/Rproject/Portscan/dataset_7.csv",sep=",",dec=".")
ds_PortScan = ds_PortScan[1:50000,]

#SAVE
ds_PortScan$Destination.Port   <- NULL 
ds_PortScan$Protocol        <- NULL            
ds_PortScan$Average.Packet.Size <- NULL
ds_PortScan$Max.Packet.Length    <- NULL       
ds_PortScan$Min.Packet.Length   <- NULL        
ds_PortScan$Bwd.Packet.Length.Mean <- NULL     
ds_PortScan$Fwd.Packet.Length.Mean   <- NULL   
ds_PortScan$Source.Port      <- NULL           
ds_PortScan$Total.Backward.Packets  <- NULL    
ds_PortScan$Total.Fwd.Packets        <- NULL   

#DELETE?
ds_PortScan$Destination.IP    <- NULL          
ds_PortScan$Timestamp <- NULL
#DELETE
ds_PortScan$Init_Win_bytes_forward <- NULL  
ds_PortScan$PSH.Flag.Count <- NULL
ds_PortScan$Bwd.Packets.s <- NULL
ds_PortScan$ACK.Flag.Count <- NULL             
ds_PortScan$Active.Mean <- NULL                
ds_PortScan$Active.Max <- NULL                 
ds_PortScan$Bwd.Header.Length  <- NULL         
ds_PortScan$Bwd.IAT.Max   <- NULL              
ds_PortScan$Bwd.IAT.Mean  <- NULL              
ds_PortScan$Bwd.IAT.Total <- NULL              
ds_PortScan$act_data_pkt_fwd <- NULL           
ds_PortScan$Active.Min  <- NULL                
ds_PortScan$Active.Std <- NULL                 
ds_PortScan$Avg.Bwd.Segment.Size  <- NULL      
ds_PortScan$Avg.Fwd.Segment.Size  <- NULL      
ds_PortScan$Bwd.Avg.Bulk.Rate     <- NULL      
ds_PortScan$Bwd.Avg.Bytes.Bulk    <- NULL      
ds_PortScan$Bwd.Avg.Packets.Bulk   <- NULL     
ds_PortScan$Bwd.IAT.Min    <- NULL             
ds_PortScan$Bwd.IAT.Std     <- NULL            
ds_PortScan$Bwd.Packet.Length.Max  <- NULL     
ds_PortScan$Bwd.Packet.Length.Min   <- NULL    
ds_PortScan$Bwd.PSH.Flags <- NULL              
ds_PortScan$Bwd.URG.Flags  <- NULL             
ds_PortScan$CWE.Flag.Count   <- NULL           
ds_PortScan$Down.Up.Ratio  <- NULL             
ds_PortScan$ECE.Flag.Count   <- NULL           
ds_PortScan$FIN.Flag.Count   <- NULL           
ds_PortScan$Flow.Bytes.s    <- NULL            
ds_PortScan$Flow.IAT.Max   <- NULL             
ds_PortScan$Flow.ID    <- NULL                 
ds_PortScan$Flow.Packets.s   <- NULL           
ds_PortScan$Fwd.Avg.Bulk.Rate  <- NULL         
ds_PortScan$Fwd.Avg.Bytes.Bulk  <- NULL        
ds_PortScan$Fwd.Avg.Packets.Bulk  <- NULL      
ds_PortScan$Fwd.Header.Length  <- NULL         
ds_PortScan$Fwd.Header.Length.1  <- NULL       
ds_PortScan$Fwd.IAT.Max   <- NULL              
ds_PortScan$Fwd.IAT.Mean   <- NULL             
ds_PortScan$Fwd.IAT.Std    <- NULL             
ds_PortScan$Fwd.IAT.Total   <- NULL            
ds_PortScan$Fwd.Packet.Length.Max    <- NULL   
ds_PortScan$Fwd.Packet.Length.Min    <- NULL   
ds_PortScan$Fwd.Packet.Length.Std  <- NULL     
ds_PortScan$Fwd.Packets.s   <- NULL            
ds_PortScan$Fwd.PSH.Flags   <- NULL            
ds_PortScan$Fwd.URG.Flags  <- NULL             
ds_PortScan$Idle.Max     <- NULL               
ds_PortScan$Idle.Mean    <- NULL               
ds_PortScan$Idle.Min    <- NULL                
ds_PortScan$Idle.Std    <- NULL                
ds_PortScan$Init_Win_bytes_backward  <- NULL   
ds_PortScan$min_seg_size_forward   <- NULL     
ds_PortScan$Packet.Length.Mean    <- NULL     
ds_PortScan$Packet.Length.Std   <- NULL        
ds_PortScan$Packet.Length.Variance   <- NULL   
ds_PortScan$RST.Flag.Count   <- NULL                    
ds_PortScan$Subflow.Bwd.Bytes    <- NULL       
ds_PortScan$Subflow.Bwd.Packets   <- NULL     
ds_PortScan$Subflow.Fwd.Bytes      <- NULL     
ds_PortScan$Subflow.Fwd.Packets    <- NULL     
ds_PortScan$SYN.Flag.Count     <- NULL         
ds_PortScan$Total.Length.of.Bwd.Packets <- NULL
ds_PortScan$Total.Length.of.Fwd.Packets <- NULL
ds_PortScan$URG.Flag.Count          <- NULL   
ds_PortScan$Bwd.Packet.Length.Std       <- NULL
ds_PortScan$Flow.Duration               <- NULL
ds_PortScan$Flow.IAT.Mean               <- NULL
ds_PortScan$Flow.IAT.Min                <- NULL
ds_PortScan$Flow.IAT.Std                <- NULL
ds_PortScan$Fwd.IAT.Min                 <- NULL


# 192로 시작하는 ip 삭제
ds_PortScan <- ds_PortScan[-grep("^192",ds_PortScan$Source.IP),]
View(ds_PortScan)

# Factor으로 변환

ds_PortScan$Label = factor(ds_PortScan$Label)
ds_PortScan$Source.IP = factor(ds_PortScan$Source.IP)
ds_PortScan$Protocol = factor(ds_PortScan$Protocol)

# Remove?
ds_PortScan$Destination.IP = factor(ds_PortScan$Destination.IP)
ds_PortScan$Timestamp = factor(ds_PortScan$Timestamp)

# Data Partitioning
partition = createDataPartition(y = ds_PortScan$Label, p = 0.7, list = F)
ds_PortScan_Train = ds_PortScan[partition, ]
ds_PortScan_Test = ds_PortScan[-partition, ]


# classification with DecisionTree
install.packages("C50")
library(C50)

C50Train = C5.0(Label~., data = ds_PortScan_Train)
summary(C50Train)
plot(C50Train)

C50Test = predict(C50Train, ds_PortScan_Test)
table(C50Test, ds_PortScan_Test$Label)

##################################################################

# classification with RandomForest
library(randomForest)

# Dataset for RandomForest
forest_trained = randomForest(Label~., data = ds_PortScan_Train, ntree = 100)
forest_trained

plot(forest_trained, ylim = range(-0.5:0.5))
legend("topright", colnames(forest_trained$err.rate),col=1:3,cex=1,fill=1:4)
treesize(forest_trained)

forest_predict = predict(forest_trained, ds_PortScan_Test[1:11])

confusionMatrix(ds_PortScan_Test$Label, forest_predict)

##################################################################

# classification with SVM
library(e1071)

# SVM classification
s = svm(Label~., data = ds_PortScan_Train)

plot(s, data = ds_PortScan_Train, Source.Port~Destination.Port)
print(s)

svm_predict_Train = predict(s, ds_PortScan_Train)
table(svm_predict_Train, ds_PortScan_Train$Label)

svm_predict_Test = predict(s, ds_PortScan_Test)
table(svm_predict_Test, ds_PortScan_Test$Label)


