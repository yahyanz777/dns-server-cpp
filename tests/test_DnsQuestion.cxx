#include <gtest/gtest.h>

#include "DnsQuestion.hpp"
#include "BytePacketBuffer.hpp"
#include <cstdint>


namespace {

TEST(DnsQuestionTest, ParsesARecordQuestion)
{
	// www.example.com, followed by QTYPE=A and QCLASS=IN.
	BytePacketBuffer buffer{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm', 0,
		0, 1,
		0, 1};
	DnsQuestion question = DnsQuestion::read(buffer);

	EXPECT_EQ(question.getName(), "www.example.com");
	EXPECT_EQ(question.getType(), QuestionType::A);
	EXPECT_EQ(question.getClass(), 1);
}

TEST(DnsQuestionTest, ParsesRootQuestion)
{
	BytePacketBuffer buffer{0, 0, 28, 0, 1};

	DnsQuestion question = DnsQuestion::read(buffer);

	EXPECT_EQ(question.getName(), ".");
	EXPECT_EQ(question.getType(), QuestionType::AAAA);
	EXPECT_EQ(question.getClass(), 1);
}

TEST(DnsQuestionTest, RejectsTruncatedQuestion)
{
	BytePacketBuffer buffer{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a'};

	EXPECT_THROW(DnsQuestion::read(buffer), std::out_of_range);
}

} 
